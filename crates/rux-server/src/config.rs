//! Lua 5.1 configuration loading and the server-side subset of Rex's Lua API.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mlua::{Function, Lua, LuaSerdeExt, RegistryKey, Table, Value as LuaValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub type ApiCall = Arc<dyn Fn(String, Value) -> Result<Value, String> + Send + Sync>;

struct LuaAction {
    metadata: Value,
    function: RegistryKey,
}

#[derive(Default)]
struct Builder {
    bindings: Vec<Value>,
    removals: Vec<Value>,
    modes: Vec<Value>,
    hosts: Vec<Value>,
    actions: Vec<LuaAction>,
    key_functions: Vec<(String, RegistryKey)>,
    diagnostics: Vec<Value>,
    next_function_binding: u64,
    loading: bool,
    invoke_depth: u32,
}

pub struct LuaConfig {
    pub path: PathBuf,
    pub exists: bool,
    pub generation: u64,
    pub hash: String,
    lua: Lua,
    builder: Arc<Mutex<Builder>>,
    api_call: Arc<Mutex<Option<ApiCall>>>,
    action_context: Arc<Mutex<Value>>,
    client_actions: Arc<Mutex<Vec<Value>>>,
    in_action: Arc<AtomicBool>,
}

impl LuaConfig {
    pub fn default_path() -> PathBuf {
        if let Some(path) = std::env::var_os("REX_CONFIG") {
            return PathBuf::from(path);
        }
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(dir).join("rex/init.lua");
        }
        std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".config/rex/init.lua"))
            .unwrap_or_else(|| PathBuf::from("rex/init.lua"))
    }

    pub fn load(path: PathBuf, generation: u64, instance_id: &str) -> Self {
        let (source, exists, hash, read_error) = match std::fs::read(&path) {
            Ok(bytes) => {
                let hash = format!("{:x}", Sha256::digest(&bytes));
                match String::from_utf8(bytes) {
                    Ok(source) => (Some(source), true, hash, None),
                    Err(err) => (
                        None,
                        true,
                        hash,
                        Some(format!("config is not UTF-8: {err}")),
                    ),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                (None, false, String::new(), None)
            }
            Err(err) => (None, false, String::new(), Some(err.to_string())),
        };

        let lua = Lua::new();
        let builder = Arc::new(Mutex::new(Builder::default()));
        let api_call = Arc::new(Mutex::new(None));
        let action_context = Arc::new(Mutex::new(Value::Null));
        let client_actions = Arc::new(Mutex::new(Vec::new()));
        let in_action = Arc::new(AtomicBool::new(false));
        builder.lock().unwrap().loading = true;
        if let Err(err) = install_api(
            &lua,
            &path,
            builder.clone(),
            api_call.clone(),
            action_context.clone(),
            client_actions.clone(),
            in_action.clone(),
            instance_id,
        ) {
            builder.lock().unwrap().diagnostics.push(json!({
                "severity": "error",
                "message": format!("registering Lua API: {err}"),
            }));
        }
        if let Some(error) = read_error {
            builder.lock().unwrap().diagnostics.push(json!({
                "severity": "error",
                "source": path.display().to_string(),
                "message": error,
            }));
        } else if let Some(source) = source {
            if let Err(err) = lua.load(&source).set_name(path.to_string_lossy()).exec() {
                builder.lock().unwrap().diagnostics.push(json!({
                    "severity": "error",
                    "source": path.display().to_string(),
                    "message": err.to_string(),
                }));
            }
        }
        builder.lock().unwrap().loading = false;

        Self {
            path,
            exists,
            generation,
            hash,
            lua,
            builder,
            api_call,
            action_context,
            client_actions,
            in_action,
        }
    }

    pub fn reload(&mut self, instance_id: &str) {
        let next = Self::load(self.path.clone(), self.generation + 1, instance_id);
        *self = next;
    }

    pub fn bindings(&self) -> Vec<Value> {
        self.builder.lock().unwrap().bindings.clone()
    }

    pub fn removals(&self) -> Vec<Value> {
        self.builder.lock().unwrap().removals.clone()
    }

    pub fn modes(&self) -> Vec<Value> {
        self.builder.lock().unwrap().modes.clone()
    }

    pub fn hosts(&self) -> Vec<Value> {
        self.builder.lock().unwrap().hosts.clone()
    }

    pub fn diagnostics(&self) -> Vec<Value> {
        self.builder.lock().unwrap().diagnostics.clone()
    }

    pub fn actions(&self) -> Vec<Value> {
        self.builder
            .lock()
            .unwrap()
            .actions
            .iter()
            .map(|action| action.metadata.clone())
            .collect()
    }

    pub fn status(&self) -> Value {
        json!({ "generation": self.generation, "hash": self.hash })
    }

    pub fn keymap_config(&self, instance_id: &str) -> Value {
        json!({
            "path": self.path,
            "exists": self.exists,
            "generation": self.generation,
            "instance_id": instance_id,
            "hash": self.hash,
        })
    }

    pub fn has_action(&self, name: &str) -> bool {
        self.builder
            .lock()
            .unwrap()
            .actions
            .iter()
            .any(|action| action.metadata.get("name").and_then(Value::as_str) == Some(name))
    }

    pub fn has_key_functions(&self) -> bool {
        !self.builder.lock().unwrap().key_functions.is_empty()
    }

    pub fn invoke_action(
        &self,
        name: &str,
        context: Value,
        args: Value,
        api_call: ApiCall,
    ) -> Result<(Value, Vec<Value>), String> {
        let function = {
            let builder = self.builder.lock().unwrap();
            let action = builder
                .actions
                .iter()
                .find(|action| action.metadata.get("name").and_then(Value::as_str) == Some(name))
                .ok_or_else(|| format!("action {name} not found"))?;
            self.lua
                .registry_value::<Function>(&action.function)
                .map_err(|err| err.to_string())?
        };
        *self.api_call.lock().unwrap() = Some(api_call);
        *self.action_context.lock().unwrap() = context.clone();
        self.client_actions.lock().unwrap().clear();
        self.in_action.store(true, Ordering::SeqCst);
        let result = (|| {
            let context = self.lua.to_value(&context).map_err(|err| err.to_string())?;
            let args = self.lua.to_value(&args).map_err(|err| err.to_string())?;
            let result = function
                .call::<LuaValue>((context, args))
                .map_err(|err| err.to_string())?;
            self.lua
                .from_value::<Value>(result)
                .map_err(|err| err.to_string())
        })();
        self.in_action.store(false, Ordering::SeqCst);
        *self.api_call.lock().unwrap() = None;
        *self.action_context.lock().unwrap() = Value::Null;
        let queued = std::mem::take(&mut *self.client_actions.lock().unwrap());
        result.map(|result| (result, queued))
    }

    pub fn invoke_key_function(
        &self,
        id: &str,
        context: Value,
        event: Value,
        api_call: ApiCall,
    ) -> Result<(Value, Vec<Value>), String> {
        let function = {
            let builder = self.builder.lock().unwrap();
            let (_, key) = builder
                .key_functions
                .iter()
                .find(|(key_id, _)| key_id == id)
                .ok_or_else(|| format!("key function {id} not found"))?;
            self.lua
                .registry_value::<Function>(key)
                .map_err(|err| err.to_string())?
        };
        *self.api_call.lock().unwrap() = Some(api_call);
        *self.action_context.lock().unwrap() = context.clone();
        self.client_actions.lock().unwrap().clear();
        let result = (|| {
            let context = self.lua.to_value(&context).map_err(|err| err.to_string())?;
            let event = self.lua.to_value(&event).map_err(|err| err.to_string())?;
            let result = function
                .call::<LuaValue>((context, event))
                .map_err(|err| err.to_string())?;
            self.lua
                .from_value::<Value>(result)
                .map_err(|err| err.to_string())
        })();
        *self.api_call.lock().unwrap() = None;
        *self.action_context.lock().unwrap() = Value::Null;
        let queued = std::mem::take(&mut *self.client_actions.lock().unwrap());
        result.map(|result| (result, queued))
    }
}

fn install_api(
    lua: &Lua,
    config_path: &Path,
    builder: Arc<Mutex<Builder>>,
    api_call: Arc<Mutex<Option<ApiCall>>>,
    action_context: Arc<Mutex<Value>>,
    client_actions: Arc<Mutex<Vec<Value>>>,
    in_action: Arc<AtomicBool>,
    instance_id: &str,
) -> mlua::Result<()> {
    crate::script::install_lua51_compat(lua)?;
    let rex = lua.create_table()?;
    let source = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("init.lua")
        .to_string();

    {
        let builder = builder.clone();
        let source = source.clone();
        rex.set(
            "bind",
            lua.create_function_mut(
                move |lua, (key, target, args): (String, LuaValue, Option<LuaValue>)| {
                    let loading = builder.lock().unwrap().loading;
                    if !loading && !matches!(target, LuaValue::Function(_)) {
                        return Err(mlua::Error::RuntimeError(
                            "rex.bind: only function bindings are available after the configuration file has loaded"
                                .into(),
                        ));
                    }
                    let keys_part = key.split_once('/');
                    let (mode, key) = match keys_part {
                        Some((mode, key)) if !mode.is_empty() => (Some(mode), key),
                        _ => (None, key.as_str()),
                    };
                    let keys: Vec<String> = key.split('>').map(str::to_string).collect();
                    if keys.is_empty() || keys.iter().any(String::is_empty) {
                        return Err(mlua::Error::RuntimeError("rex.bind: invalid key".into()));
                    }
                    let mut builder = builder.lock().unwrap();
                    let (target_name, binding_args) = match target {
                        LuaValue::String(name) => {
                            let binding_args = if let Some(args) =
                                args.filter(|args| !matches!(args, LuaValue::Nil))
                            {
                                Some(lua.from_value::<Value>(args)?)
                            } else {
                                None
                            };
                            (name.to_str()?.to_string(), binding_args)
                        }
                        LuaValue::Function(function) => {
                            if mode.is_some()
                                || args
                                    .as_ref()
                                    .is_some_and(|args| !matches!(args, LuaValue::Nil))
                            {
                                return Err(mlua::Error::RuntimeError(
                                    "rex.bind: function bindings cannot have a mode or args".into(),
                                ));
                            }
                            let id = format!("key-{}", builder.next_function_binding);
                            builder.next_function_binding += 1;
                            builder
                                .key_functions
                                .push((id.clone(), lua.create_registry_value(function)?));
                            (
                                "client.key.forward".to_string(),
                                Some(json!({ "binding_id": id })),
                            )
                        }
                        _ => {
                            return Err(mlua::Error::RuntimeError(
                                "rex.bind: action must be a string or function".into(),
                            ));
                        }
                    };
                    let mut binding = json!({
                        "keys": keys,
                        "action": target_name,
                        "source": format!("{source}:1"),
                    });
                    if let Some(mode) = mode {
                        binding["mode"] = json!(mode);
                        if !builder.modes.iter().any(|existing| {
                            existing.get("name").and_then(Value::as_str) == Some(mode)
                        }) {
                            builder.modes.push(json!({
                                "name": mode,
                                "exclusive": false,
                                "source": format!("{source}:1"),
                            }));
                        }
                    }
                    if let Some(args) = binding_args {
                        binding["args"] = args;
                    }
                    builder.bindings.push(binding);
                    Ok(())
                },
            )?,
        )?;
    }

    {
        let builder = builder.clone();
        let source = source.clone();
        rex.set(
            "mode",
            lua.create_function_mut(move |lua, (name, options): (String, Option<Table>)| {
                if !builder.lock().unwrap().loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.mode is only available while the configuration file is loading".into(),
                    ));
                }
                if name.is_empty() || name == "root" {
                    return Err(mlua::Error::RuntimeError(
                        "rex.mode: invalid mode name".into(),
                    ));
                }
                let exclusive = options
                    .as_ref()
                    .and_then(|options| options.get::<Option<bool>>("exclusive").ok().flatten())
                    .unwrap_or(false);
                builder.lock().unwrap().modes.push(json!({
                    "name": name,
                    "exclusive": exclusive,
                    "source": format!("{source}:1"),
                }));
                let _ = lua;
                Ok(())
            })?,
        )?;
    }

    {
        let builder = builder.clone();
        let source = source.clone();
        rex.set(
            "host",
            lua.create_function_mut(move |lua, host: Table| {
                if !builder.lock().unwrap().loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.host is only available while the configuration file is loading".into(),
                    ));
                }
                let mut host: Value = lua.from_value(LuaValue::Table(host))?;
                if host.get("endpoints").is_none() {
                    if let Some(endpoint) = host.get("endpoint").cloned() {
                        host["endpoints"] = json!([endpoint]);
                    }
                    if let Some(object) = host.as_object_mut() {
                        object.remove("endpoint");
                    }
                }
                if host.get("id").is_none()
                    && let Some(label) = host.get("label").and_then(Value::as_str)
                {
                    let digest = Sha256::digest(format!("{source}:{label}").as_bytes());
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&digest[..16]);
                    bytes[6] = (bytes[6] & 0x0f) | 0x50;
                    bytes[8] = (bytes[8] & 0x3f) | 0x80;
                    host["id"] = json!(format!("host:{}", uuid::Uuid::from_bytes(bytes)));
                }
                host["source"] = json!(format!("{source}:1"));
                builder.lock().unwrap().hosts.push(host);
                Ok(())
            })?,
        )?;
    }

    {
        let builder = builder.clone();
        rex.set(
            "action",
            lua.create_function_mut(move |lua, definition: Table| {
                if !builder.lock().unwrap().loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.action is only available while the configuration file is loading"
                            .into(),
                    ));
                }
                let name: String = definition.get("name")?;
                let title: String = definition.get("title")?;
                let run: Function = definition.get("run")?;
                if name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(mlua::Error::RuntimeError(
                        "rex.action: invalid action name".into(),
                    ));
                }
                if title.is_empty() {
                    return Err(mlua::Error::RuntimeError(
                        "rex.action: title is required".into(),
                    ));
                }
                let mut metadata = json!({ "name": name, "kind": "lua", "title": title });
                for field in ["description", "category", "keywords", "repeats", "args"] {
                    if let Ok(value) = definition.get::<LuaValue>(field)
                        && !matches!(value, LuaValue::Nil)
                    {
                        metadata[field] = lua.from_value(value)?;
                    }
                }
                let function = lua.create_registry_value(run)?;
                let mut builder = builder.lock().unwrap();
                if builder.actions.iter().any(|action| {
                    action.metadata.get("name").and_then(Value::as_str) == Some(&name)
                }) {
                    return Err(mlua::Error::RuntimeError(format!(
                        "rex.action: duplicate action {name}"
                    )));
                }
                builder.actions.push(LuaAction { metadata, function });
                Ok(())
            })?,
        )?;
    }

    {
        let builder = builder.clone();
        rex.set(
            "unbind",
            lua.create_function_mut(move |lua, (value, target): (LuaValue, Option<LuaValue>)| {
                let mut removal: Value = match value {
                    LuaValue::String(key) => {
                        let key = key.to_str()?.to_string();
                        let (mode, key) = match key.split_once('/') {
                            Some((mode, key)) => (Some(mode.to_string()), key.to_string()),
                            None => (None, key),
                        };
                        let mut removal = json!({
                            "keys": key.split('>').collect::<Vec<_>>(),
                        });
                        if let Some(mode) = mode {
                            removal["mode"] = json!(mode);
                        }
                        removal
                    }
                    LuaValue::Table(table) => lua.from_value(LuaValue::Table(table))?,
                    LuaValue::Function(function) => {
                        let builder_guard = builder.lock().unwrap();
                        let ids = function_binding_ids(lua, &builder_guard, &function);
                        if ids.is_empty() {
                            return Ok(0);
                        }
                        json!({ "fn_binding_ids": ids })
                    }
                    _ => {
                        return Err(mlua::Error::RuntimeError(
                            "rex.unbind: expected string, table, or function".into(),
                        ));
                    }
                };
                if let Some(target) = target.filter(|target| !matches!(target, LuaValue::Nil)) {
                    match target {
                        LuaValue::String(target) => {
                            removal["action"] = json!(target.to_str()?.to_string());
                        }
                        LuaValue::Function(function) => {
                            let builder_guard = builder.lock().unwrap();
                            let ids = function_binding_ids(lua, &builder_guard, &function);
                            if ids.is_empty() {
                                return Ok(0);
                            }
                            removal["fn_binding_ids"] = json!(ids);
                        }
                        _ => {
                            return Err(mlua::Error::RuntimeError(
                                "rex.unbind: target must be an action name or a function".into(),
                            ));
                        }
                    }
                }
                let mut builder = builder.lock().unwrap();
                let loading = builder.loading;
                let before = builder.bindings.len();
                builder.bindings.retain(|binding| {
                    let matches = binding_matches_removal(binding, &removal);
                    if !matches {
                        return true;
                    }
                    if loading {
                        return false;
                    }
                    binding.get("action").and_then(Value::as_str) != Some("client.key.forward")
                });
                let removed = before - builder.bindings.len();
                if loading {
                    if removal.get("keys").is_none()
                        && let Some(mode) = removal.get("mode").and_then(Value::as_str)
                    {
                        builder.modes.retain(|existing| {
                            existing.get("name").and_then(Value::as_str) != Some(mode)
                        });
                    }
                    builder.removals.push(removal);
                }
                Ok(removed)
            })?,
        )?;
    }

    {
        let builder = builder.clone();
        rex.set(
            "on",
            lua.create_function_mut(move |_, _: (LuaValue, LuaValue)| {
                let mut builder = builder.lock().unwrap();
                if !builder.loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.on is only available while the configuration file is loading".into(),
                    ));
                }
                builder.diagnostics.push(json!({
                    "severity": "warning",
                    "message": "rex.on has no effect in a configuration file",
                }));
                Ok(())
            })?,
        )?;
    }
    {
        let builder = builder.clone();
        rex.set(
            "bindings",
            lua.create_function_mut(move |lua, filter: Option<Table>| {
                if !builder.lock().unwrap().loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.bindings is only available while the configuration file is loading"
                            .into(),
                    ));
                }
                let filter: Value = match filter {
                    Some(filter) => lua.from_value(LuaValue::Table(filter))?,
                    None => json!({}),
                };
                let builder = builder.lock().unwrap();
                let list = lua.create_table()?;
                let mut index = 1;
                for binding in &builder.bindings {
                    let key = binding
                        .get("keys")
                        .and_then(Value::as_array)
                        .map(|keys| {
                            keys.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(">")
                        })
                        .unwrap_or_default();
                    let mode = binding.get("mode").and_then(Value::as_str);
                    let action_name = binding.get("action").and_then(Value::as_str);
                    if let Some(expected) = filter.get("key").and_then(Value::as_str)
                        && expected != key
                    {
                        continue;
                    }
                    if let Some(expected) = filter.get("mode").and_then(Value::as_str)
                        && mode != Some(expected)
                    {
                        continue;
                    }
                    if let Some(expected) = filter.get("action").and_then(Value::as_str)
                        && action_name != Some(expected)
                    {
                        continue;
                    }
                    let row = lua.create_table()?;
                    row.set("key", key)?;
                    if let Some(mode) = mode {
                        row.set("mode", mode)?;
                    }
                    row.set(
                        "source",
                        binding.get("source").and_then(Value::as_str).unwrap_or(""),
                    )?;
                    if action_name == Some("client.key.forward") {
                        let binding_id = binding
                            .get("args")
                            .and_then(|args| args.get("binding_id"))
                            .and_then(Value::as_str);
                        if let Some(binding_id) = binding_id
                            && let Some((_, key)) = builder
                                .key_functions
                                .iter()
                                .find(|(id, _)| id == binding_id)
                            && let Ok(func) = lua.registry_value::<Function>(key)
                        {
                            row.set("fn", func)?;
                        }
                    } else if let Some(action_name) = action_name {
                        row.set("action", action_name)?;
                        if let Some(args) = binding.get("args") {
                            row.set("args", lua.to_value(args)?)?;
                        }
                    }
                    list.set(index, row)?;
                    index += 1;
                }
                Ok(list)
            })?,
        )?;
    }
    {
        let builder = builder.clone();
        rex.set(
            "modes",
            lua.create_function_mut(move |lua, _: ()| {
                if !builder.lock().unwrap().loading {
                    return Err(mlua::Error::RuntimeError(
                        "rex.modes is only available while the configuration file is loading"
                            .into(),
                    ));
                }
                lua.to_value(&builder.lock().unwrap().modes)
            })?,
        )?;
    }

    install_call_api(
        lua,
        &rex,
        api_call,
        action_context,
        client_actions,
        in_action,
        builder,
    )?;
    rex.set("instance_id", instance_id)?;
    lua.globals().set("rex", rex)?;

    // Keep config loading from invoking arbitrary shell commands through the
    // two APIs Rex itself disables. `rex.exec` is not wired until a managed
    // process API is available.
    let io: Table = lua.globals().get("io")?;
    io.set(
        "popen",
        lua.create_function(|_, _: LuaValue| {
            Err::<LuaValue, _>(mlua::Error::RuntimeError("io.popen is disabled".into()))
        })?,
    )?;
    let os: Table = lua.globals().get("os")?;
    os.set(
        "execute",
        lua.create_function(|_, _: LuaValue| {
            Err::<LuaValue, _>(mlua::Error::RuntimeError("os.execute is disabled".into()))
        })?,
    )?;

    if let Some(parent) = config_path.parent() {
        let package: Table = lua.globals().get("package")?;
        let old_path: String = package.get("path")?;
        let prefix = format!(
            "{}/?.lua;{}/?/init.lua;",
            parent.display(),
            parent.display()
        );
        package.set("path", format!("{prefix}{old_path}"))?;
    }
    Ok(())
}

fn install_call_api(
    lua: &Lua,
    rex: &Table,
    api_call: Arc<Mutex<Option<ApiCall>>>,
    action_context: Arc<Mutex<Value>>,
    client_actions: Arc<Mutex<Vec<Value>>>,
    in_action: Arc<AtomicBool>,
    builder: Arc<Mutex<Builder>>,
) -> mlua::Result<()> {
    let call_context = api_call.clone();
    let context = action_context.clone();
    rex.set(
        "call",
        lua.create_function_mut(move |lua, (method, args): (String, Option<Table>)| {
            let mut payload = table_payload(lua, args)?;
            add_default_session(&mut payload, &context.lock().unwrap());
            invoke_api(lua, &call_context, &method, payload)
        })?,
    )?;

    let session = lua.create_table()?;
    const SESSION_METHODS: &[&str] = &[
        "view",
        "list_blocks",
        "list_clients",
        "describe_block",
        "new_window",
        "new_split",
        "new_block",
        "new_layer",
        "close_window",
        "close_layer",
        "move_block",
        "swap_blocks",
        "detach_block",
        "float_block",
        "zoom_block",
        "resize_pane",
        "resize_layer",
        "raise_layer",
        "lower_layer",
        "move_window",
        "focus_block",
        "focus_window",
        "focus_direction",
        "focus_next_pane",
        "focus_previous_pane",
        "focus_next_window",
        "focus_previous_window",
        "set_label",
        "set_window_label",
        "set_block_label",
        "attach",
        "detach",
        "help",
    ];
    for method in SESSION_METHODS {
        let method_name = format!("session.{method}");
        let call_context = api_call.clone();
        let context = action_context.clone();
        session.set(
            *method,
            lua.create_function_mut(move |lua, args: Option<Table>| {
                let mut payload = table_payload(lua, args)?;
                add_default_session(&mut payload, &context.lock().unwrap());
                invoke_api(lua, &call_context, &method_name, payload)
            })?,
        )?;
    }
    rex.set("session", session)?;

    let block = lua.create_table()?;
    let call_context = api_call.clone();
    let context = action_context.clone();
    block.set(
        "call",
        lua.create_function_mut(
            move |lua, (creator, method, args): (String, String, Option<Table>)| {
                let args = table_payload(lua, args)?;
                let _ = creator;
                let ctx = context.lock().unwrap();
                let mut payload = json!({
                    "method": method,
                    "args": args,
                });
                if let Some(session_id) = ctx.get("session_id").filter(|value| !value.is_null()) {
                    payload["session_id"] = session_id.clone();
                }
                if let Some(block_id) = ctx.get("block_id").filter(|value| !value.is_null()) {
                    payload["block_id"] = block_id.clone();
                }
                if payload.get("block_id").is_none() {
                    return Ok((LuaValue::Nil, Some("block_id is required".to_string())));
                }
                invoke_api(lua, &call_context, "block.method", payload)
            },
        )?,
    )?;
    rex.set("block", block)?;

    let layout = lua.create_table()?;
    layout.set(
        "block",
        lua.create_function(|lua, block: Table| {
            let block: Value = lua.from_value(LuaValue::Table(block))?;
            lua.to_value(&json!({ "block": block }))
        })?,
    )?;
    for (name, direction) in [("horizontal", "horizontal"), ("vertical", "vertical")] {
        layout.set(
            name,
            lua.create_function(
                move |lua, (ratio, before, after): (f64, LuaValue, LuaValue)| {
                    let before: Value = lua.from_value(before)?;
                    let after: Value = lua.from_value(after)?;
                    lua.to_value(&json!({
                        "split": {
                            "direction": direction,
                            "ratio": ratio,
                            "before": before,
                            "after": after,
                        }
                    }))
                },
            )?,
        )?;
    }
    rex.set("layout", layout)?;

    let client = lua.create_table()?;
    client.set(
        "queue",
        lua.create_function_mut(move |lua, (name, args): (String, Option<Table>)| {
            if !in_action.load(Ordering::SeqCst) {
                return Err(mlua::Error::RuntimeError(
                    "rex.client.queue is only available inside an action".into(),
                ));
            }
            let mut action = json!({ "action": name });
            if let Some(args) = args {
                action["args"] = lua.from_value(LuaValue::Table(args))?;
            }
            client_actions.lock().unwrap().push(action);
            Ok(())
        })?,
    )?;
    rex.set("client", client)?;

    let json_api = lua.create_table()?;
    json_api.set(
        "encode",
        lua.create_function(|lua, (value, opts): (LuaValue, Option<Table>)| {
            let value: Value = match lua.from_value(value) {
                Ok(value) => value,
                Err(error) => return Ok((LuaValue::Nil, Some(error.to_string()))),
            };
            let indent = opts
                .as_ref()
                .and_then(|opts| opts.get::<Option<bool>>("indent").ok().flatten())
                .unwrap_or(false);
            let text = if indent {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            };
            match text {
                Ok(text) => Ok((
                    LuaValue::String(lua.create_string(text)?),
                    Option::<String>::None,
                )),
                Err(error) => Ok((LuaValue::Nil, Some(error.to_string()))),
            }
        })?,
    )?;
    json_api.set(
        "decode",
        lua.create_function(
            |lua, text: String| match serde_json::from_str::<Value>(&text) {
                Ok(value) => Ok((lua.to_value(&json_for_lua(value))?, Option::<String>::None)),
                Err(error) => Ok((LuaValue::Nil, Some(error.to_string()))),
            },
        )?,
    )?;
    rex.set("json", json_api)?;

    rex.set(
        "log",
        lua.create_function(|_, args: mlua::MultiValue| {
            let level = if args.len() >= 2 {
                match &args[0] {
                    LuaValue::String(text) => text
                        .to_str()
                        .map(|text| text.to_string())
                        .unwrap_or_default(),
                    _ => "info".to_string(),
                }
            } else {
                "info".to_string()
            };
            let message = if args.len() >= 2 {
                lua_text(&args[1])
            } else if args.len() == 1 {
                lua_text(&args[0])
            } else {
                String::new()
            };
            match level.as_str() {
                "debug" => tracing::debug!(target: "rux_lua", "{message}"),
                "warn" => tracing::warn!(target: "rux_lua", "{message}"),
                "error" => tracing::error!(target: "rux_lua", "{message}"),
                _ => tracing::info!(target: "rux_lua", "{message}"),
            }
            Ok(())
        })?,
    )?;
    rex.set(
        "exec",
        lua.create_function(
            |lua, (argv, options): (Vec<String>, Option<Table>)| match exec_command(argv, options) {
                Ok(result) => Ok((lua.to_value(&result)?, Option::<String>::None)),
                Err(error) => Ok((LuaValue::Nil, Some(error))),
            },
        )?,
    )?;
    crate::script::install_exec_start(lua, rex)?;
    {
        let builder = builder.clone();
        let action_context = action_context.clone();
        rex.set(
            "invoke",
            lua.create_function_mut(move |lua, (name, args): (String, Option<Table>)| {
                if builder.lock().unwrap().loading {
                    builder.lock().unwrap().diagnostics.push(json!({
                        "severity": "warning",
                        "message": "rex.invoke does nothing while the configuration file is loading",
                    }));
                    return Ok((
                        LuaValue::Nil,
                        Some(
                            "rex.invoke does nothing while the configuration file is loading"
                                .to_string(),
                        ),
                    ));
                }
                if builder.lock().unwrap().invoke_depth >= 16 {
                    return Ok((LuaValue::Nil, Some("rex.invoke nested too deep".to_string())));
                }
                let function = {
                    let builder = builder.lock().unwrap();
                    let action = builder.actions.iter().find(|action| {
                        action.metadata.get("name").and_then(Value::as_str) == Some(name.as_str())
                    });
                    match action {
                        Some(action) => lua.registry_value::<Function>(&action.function)?,
                        None => {
                            return Ok((LuaValue::Nil, Some(format!("action {name} not found"))));
                        }
                    }
                };
                builder.lock().unwrap().invoke_depth += 1;
                let ctx = action_context.lock().unwrap().clone();
                let args = table_payload(lua, args)?;
                let result = function.call::<LuaValue>((lua.to_value(&ctx)?, lua.to_value(&args)?));
                {
                    let mut builder = builder.lock().unwrap();
                    builder.invoke_depth = builder.invoke_depth.saturating_sub(1);
                }
                match result {
                    Ok(value) => Ok((value, None)),
                    Err(error) => Ok((LuaValue::Nil, Some(error.to_string()))),
                }
            })?,
        )?;
    }
    {
        let builder = builder.clone();
        let action_context = action_context.clone();
        rex.set(
            "servers",
            lua.create_function(move |lua, ()| {
                lua.to_value(&server_labels(&builder, &action_context))
            })?,
        )?;
    }
    {
        let builder = builder.clone();
        let action_context = action_context.clone();
        let api_call = api_call.clone();
        rex.set(
            "server",
            lua.create_function_mut(move |lua, label: String| {
                if !server_labels(&builder, &action_context)
                    .iter()
                    .any(|host| host == &label)
                {
                    return Err(mlua::Error::RuntimeError(format!("unknown server {label}")));
                }
                let endpoints = builder
                    .lock()
                    .unwrap()
                    .hosts
                    .iter()
                    .find(|host| host.get("label").and_then(Value::as_str) == Some(label.as_str()))
                    .map(|host| {
                        let mut list: Vec<String> = host
                            .get("endpoints")
                            .and_then(Value::as_array)
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default();
                        if list.is_empty()
                            && let Some(one) = host.get("endpoint").and_then(Value::as_str)
                        {
                            list.push(one.to_string());
                        }
                        list
                    })
                    .filter(|endpoints| !endpoints.is_empty());
                let proxy = lua.create_table()?;
                let call_context = api_call.clone();
                let call_endpoints = endpoints.clone();
                proxy.set(
                    "call",
                    lua.create_function_mut(
                        move |lua, (method, args): (String, Option<Table>)| {
                            let payload = table_payload(lua, args)?;
                            match &call_endpoints {
                                Some(endpoints) => {
                                    crate::remote::invoke_lua(lua, endpoints, &method, payload)
                                }
                                None => invoke_api(lua, &call_context, &method, payload),
                            }
                        },
                    )?,
                )?;
                let session = lua.create_table()?;
                for method in SESSION_METHODS {
                    let method_name = format!("session.{method}");
                    let call_context = api_call.clone();
                    let method_endpoints = endpoints.clone();
                    session.set(
                        *method,
                        lua.create_function_mut(move |lua, args: Option<Table>| {
                            let payload = table_payload(lua, args)?;
                            match &method_endpoints {
                                Some(endpoints) => crate::remote::invoke_lua(
                                    lua,
                                    endpoints,
                                    &method_name,
                                    payload,
                                ),
                                None => invoke_api(lua, &call_context, &method_name, payload),
                            }
                        })?,
                    )?;
                }
                proxy.set("session", session)?;
                let block = lua.create_table()?;
                let call_context = api_call.clone();
                block.set(
                    "call",
                    lua.create_function_mut(
                        move |lua, (creator, method, args): (String, String, Option<Table>)| {
                            let _ = creator;
                            let args = table_payload(lua, args)?;
                            let mut payload = json!({ "method": method, "args": args });
                            if let Some(block_id) = args.get("block_id").cloned() {
                                payload["block_id"] = block_id;
                            }
                            if payload.get("block_id").is_none() {
                                return Ok((
                                    LuaValue::Nil,
                                    Some("block_id is required".to_string()),
                                ));
                            }
                            match &endpoints {
                                Some(endpoints) => crate::remote::invoke_lua(
                                    lua,
                                    endpoints,
                                    "block.method",
                                    payload,
                                ),
                                None => invoke_api(lua, &call_context, "block.method", payload),
                            }
                        },
                    )?,
                )?;
                proxy.set("block", block)?;
                Ok(proxy)
            })?,
        )?;
    }
    Ok(())
}

fn server_labels(builder: &Mutex<Builder>, context: &Mutex<Value>) -> Vec<String> {
    let ctx = context.lock().unwrap();
    if let Some(servers) = ctx.get("servers").and_then(Value::as_array) {
        let labels: Vec<String> = servers
            .iter()
            .filter_map(|server| {
                server
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        if !labels.is_empty() {
            return labels;
        }
    }
    builder
        .lock()
        .unwrap()
        .hosts
        .iter()
        .filter_map(|host| {
            host.get("label")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn lua_text(value: &LuaValue) -> String {
    match value {
        LuaValue::String(text) => text
            .to_str()
            .map(|text| text.to_string())
            .unwrap_or_default(),
        LuaValue::Integer(number) => number.to_string(),
        LuaValue::Number(number) => number.to_string(),
        LuaValue::Boolean(flag) => flag.to_string(),
        _ => String::new(),
    }
}

pub(crate) fn exec_command(argv: Vec<String>, options: Option<Table>) -> Result<Value, String> {
    if argv.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
        return Err("argv must contain a program and valid strings".into());
    }
    let timeout_secs = options
        .as_ref()
        .and_then(|options| options.get::<Option<f64>>("timeout").ok().flatten());
    if timeout_secs.is_some_and(|timeout| !timeout.is_finite() || timeout < 0.0) {
        return Err("timeout must be a non-negative number".into());
    }
    let timeout = timeout_secs.map(|seconds| Duration::from_secs_f64(seconds.min(600.0)));
    let clear_env = options
        .as_ref()
        .and_then(|options| options.get::<Option<bool>>("clear_env").ok().flatten())
        .unwrap_or(false);
    let capture_stdout = options
        .as_ref()
        .and_then(|options| options.get::<Option<bool>>("stdout").ok().flatten())
        .unwrap_or(true);
    let capture_stderr = options
        .as_ref()
        .and_then(|options| options.get::<Option<bool>>("stderr").ok().flatten())
        .unwrap_or(true);
    let stdin = options
        .as_ref()
        .and_then(|options| options.get::<Option<String>>("stdin").ok().flatten());

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    if clear_env {
        command.env_clear();
    }
    if let Some(options) = &options {
        if let Ok(Some(cwd)) = options.get::<Option<String>>("cwd") {
            command.current_dir(cwd);
        }
        if let Ok(Some(env)) = options.get::<Option<Table>>("env") {
            for pair in env.pairs::<String, LuaValue>() {
                let (key, value) = pair.map_err(|error| error.to_string())?;
                match value {
                    LuaValue::String(value) => {
                        command.env(
                            key,
                            value
                                .to_str()
                                .map_err(|error| error.to_string())?
                                .to_string(),
                        );
                    }
                    LuaValue::Boolean(false) => {
                        command.env_remove(key);
                    }
                    _ => return Err(format!("env.{key} must be a string or false")),
                }
            }
        }
    }
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let stdin_writer = stdin.and_then(|input| {
        child.stdin.take().map(|mut stream| {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = stream.write_all(input.as_bytes());
            })
        })
    });
    let stdout_reader = child.stdout.take().map(read_capped_stream);
    let stderr_reader = child.stderr.take().map(read_capped_stream);
    let start = Instant::now();
    let mut timed_out = false;
    let status = 'wait: loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if timeout.is_some_and(|limit| start.elapsed() >= limit) {
            timed_out = true;
            // SIGTERM first. SIGKILL only if the process is still alive after
            // the two seconds the Lua page specifies.
            terminate_child(&child);
            let grace_started = Instant::now();
            loop {
                if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                    break 'wait status;
                }
                if grace_started.elapsed() >= Duration::from_secs(2) {
                    let _ = child.kill();
                    break 'wait child.wait().map_err(|error| error.to_string())?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if let Some(writer) = stdin_writer {
        let _ = writer.join();
    }
    let stdout = stdout_reader
        .map(|reader| reader.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_reader
        .map(|reader| reader.join().unwrap_or_default())
        .unwrap_or_default();
    let code = status.code().unwrap_or(-1);
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(signal_name)
    };
    #[cfg(not(unix))]
    let signal: Option<String> = None;
    Ok(json!({
        "code": code,
        "signal": signal,
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
        "timed_out": timed_out,
        "ok": code == 0 && !timed_out,
    }))
}

fn read_capped_stream<R: Read + Send + 'static>(mut stream: R) -> JoinHandle<Vec<u8>> {
    const MAX_OUTPUT: usize = 1_048_576;
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(size) => {
                    let remaining = MAX_OUTPUT.saturating_sub(output.len());
                    output.extend_from_slice(&chunk[..size.min(remaining)]);
                }
            }
        }
        output
    })
}

fn terminate_child(child: &std::process::Child) {
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        kill(child.id() as i32, 15);
    }
    #[cfg(not(unix))]
    {
        let _ = child;
    }
}

#[cfg(unix)]
fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        9 => "SIGKILL",
        15 => "SIGTERM",
        _ => return format!("SIG{signal}"),
    }
    .to_string()
}

fn table_payload(lua: &Lua, table: Option<Table>) -> mlua::Result<Value> {
    match table {
        Some(table) => lua.from_value(LuaValue::Table(table)),
        None => Ok(json!({})),
    }
}

fn add_default_session(payload: &mut Value, context: &Value) {
    if !payload.is_object() {
        *payload = json!({});
    }
    if payload.get("session_id").is_none()
        && let Some(session_id) = context.get("session_id")
    {
        payload["session_id"] = session_id.clone();
    }
}

fn invoke_api(
    lua: &Lua,
    api_call: &Arc<Mutex<Option<ApiCall>>>,
    method: &str,
    payload: Value,
) -> mlua::Result<(LuaValue, Option<String>)> {
    let api = api_call.lock().unwrap().clone().ok_or_else(|| {
        mlua::Error::RuntimeError("Rex API calls are only available inside an action".into())
    })?;
    match api(method.to_string(), payload) {
        Ok(result) => Ok((lua.to_value(&result)?, None)),
        Err(error) => Ok((LuaValue::Nil, Some(error))),
    }
}

/// JSON null is Lua nil. A nil in an array is dropped, matching `rex.json.decode`.
pub(crate) fn json_for_lua(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .filter(|item| !item.is_null())
                .map(json_for_lua)
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, item)| !item.is_null())
                .map(|(key, item)| (key, json_for_lua(item)))
                .collect(),
        ),
        other => other,
    }
}

/// Find every function-binding id (`key-N`) this file gave to
/// `function`, comparing by function identity. One function can back
/// several bindings, one per `rex.bind` call.
fn function_binding_ids(lua: &Lua, builder: &Builder, function: &Function) -> Vec<String> {
    builder
        .key_functions
        .iter()
        .filter(|(_, key)| {
            lua.registry_value::<Function>(key)
                .map(|stored| stored.to_pointer() == function.to_pointer())
                .unwrap_or(false)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn binding_matches_removal(binding: &Value, removal: &Value) -> bool {
    if binding.get("mode").and_then(Value::as_str) != removal.get("mode").and_then(Value::as_str) {
        return false;
    }
    if let Some(keys) = removal.get("keys").and_then(Value::as_array)
        && binding.get("keys").and_then(Value::as_array) != Some(keys)
    {
        return false;
    }
    if let Some(action) = removal.get("action").and_then(Value::as_str)
        && binding.get("action").and_then(Value::as_str) != Some(action)
    {
        return false;
    }
    if let Some(ids) = removal.get("fn_binding_ids").and_then(Value::as_array) {
        let binding_id = binding
            .get("args")
            .and_then(|args| args.get("binding_id"))
            .and_then(Value::as_str);
        if !ids.iter().any(|id| id.as_str() == binding_id) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use mlua::Lua;
    use serde_json::Value;

    use super::exec_command;

    fn exec_with_timeout(argv: Vec<String>, seconds: f64) -> Result<Value, String> {
        let lua = Lua::new();
        let options = lua.create_table().map_err(|error| error.to_string())?;
        options
            .set("timeout", seconds)
            .map_err(|error| error.to_string())?;
        exec_command(argv, Some(options))
    }

    #[test]
    fn config_file_exposes_bindings_json_and_invoke() {
        let dir = std::env::temp_dir().join(format!("rux-lua-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("init.lua");
        std::fs::write(
            &path,
            r#"
            rex.on("terminal.bell", function() end)
            rex.bind("ctrl+g", "pane.split", { direction = "right" })
            rex.mode("work", { exclusive = true })
            rex.host{ label = "other", endpoint = "unix:///tmp/other.sock" }
            rex.action{ name = "ping", title = "Ping", run = function()
                return rex.invoke("pong")
            end }
            rex.action{ name = "pong", title = "Pong", run = function()
                return "pong"
            end }
            local found = rex.bindings({ key = "ctrl+g" })
            assert(#found == 1)
            assert(found[1].action == "pane.split")
            assert(found[1].args.direction == "right")
            assert(rex.modes()[1].name == "work")
            assert(rex.modes()[1].exclusive == true)
            assert(rex.servers()[1] == "other")
            local ignored, why = rex.invoke("ping")
            assert(ignored == nil and why)
            local text, err = rex.json.encode({ a = 1 }, { indent = true })
            assert(err == nil and text:find("\n"))
            local bad, why2 = rex.json.decode("{")
            assert(bad == nil and why2)
            local decoded = rex.json.decode("[1, null, 2]")
            assert(decoded[1] == 1 and decoded[2] == 2 and decoded[3] == nil)
            local ok_queue = pcall(function() rex.client.queue("pane.zoom") end)
            assert(ok_queue == false)
            rex.bind("ctrl+h", function() end)
            rex.action{ name = "trim", title = "Trim", run = function()
                return rex.unbind("ctrl+g") .. ":" .. rex.unbind("ctrl+h")
            end }
            rex.action{ name = "ask", title = "Ask", run = function()
                rex.client.queue("pane.zoom")
                return "asked"
            end }
            rex.log("warn", "config")
            "#,
        )
        .unwrap();
        let config = super::LuaConfig::load(path, 1, "instance");
        let diagnostics = config.diagnostics();
        assert!(
            diagnostics.iter().any(|item| {
                item["severity"] == "warning"
                    && item["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("rex.on"))
            }),
            "{diagnostics:?}"
        );
        assert!(
            diagnostics.iter().any(|item| {
                item["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("rex.invoke"))
            }),
            "{diagnostics:?}"
        );
        let api: super::ApiCall =
            std::sync::Arc::new(|_method, _payload| Ok(serde_json::json!({})));
        let (result, queued) = config
            .invoke_action(
                "ping",
                serde_json::json!({ "origin": "api" }),
                serde_json::json!({}),
                api.clone(),
            )
            .unwrap();
        assert_eq!(result, serde_json::json!("pong"));
        assert!(queued.is_empty());
        let (trimmed, _) = config
            .invoke_action(
                "trim",
                serde_json::json!({ "origin": "api" }),
                serde_json::json!({}),
                api.clone(),
            )
            .unwrap();
        assert_eq!(trimmed, serde_json::json!("0:1"));
        let (asked, queued) = config
            .invoke_action(
                "ask",
                serde_json::json!({ "origin": "api" }),
                serde_json::json!({}),
                api,
            )
            .unwrap();
        assert_eq!(asked, serde_json::json!("asked"));
        assert_eq!(queued[0]["action"], "pane.zoom");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unbind_accepts_a_function_target() {
        let dir = std::env::temp_dir().join(format!("rux-lua-unbind-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("init.lua");
        std::fs::write(
            &path,
            r#"
local f = function() return true end
rex.bind("ctrl+j", f)
rex.bind("ctrl+l", f)
rex.bind("ctrl+m", "some.action")
rex.unbind("ctrl+j", f)
rex.unbind(f)
"#,
        )
        .unwrap();
        let config = super::LuaConfig::load(path.clone(), 1, "instance");
        let bindings = config.bindings();
        assert_eq!(bindings.len(), 1, "{bindings:?}");
        assert_eq!(bindings[0]["keys"], serde_json::json!(["ctrl+m"]));
        assert_eq!(bindings[0]["action"], "some.action");

        std::fs::write(
            &path,
            r#"
local f = function() return true end
local g = function() return false end
rex.bind("ctrl+j", f)
rex.unbind("ctrl+j", g)
rex.unbind(g)
"#,
        )
        .unwrap();
        let config = super::LuaConfig::load(path, 1, "instance");
        let bindings = config.bindings();
        assert_eq!(bindings.len(), 1, "{bindings:?}");
        assert_eq!(bindings[0]["keys"], serde_json::json!(["ctrl+j"]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn exec_timeout_sends_sigterm_and_does_not_wait_out_the_grace() {
        let started = Instant::now();
        let result = exec_with_timeout(vec!["sleep".into(), "30".into()], 0.05).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["signal"], "SIGTERM");
        assert_eq!(result["ok"], false);
    }

    #[test]
    fn exec_timeout_sends_sigkill_two_seconds_after_sigterm_is_ignored() {
        let started = Instant::now();
        let result = exec_with_timeout(
            vec![
                "python3".into(),
                "-c".into(),
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
                    .into(),
            ],
            0.05,
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["signal"], "SIGKILL");
    }
}
