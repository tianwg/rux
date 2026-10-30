//! Script Lua: `rex do` and `client.set_script`.
//!
//! Configuration-file Lua stays in `config`. This module is the runtime the
//! Lua page tags as Script: event handlers, waits, timers, and `rex.exec.start`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mlua::{Lua, LuaSerdeExt, RegistryKey, Table, UserData, UserDataMethods, Value as LuaValue};
use serde_json::{Value, json};

use crate::config::{ApiCall, exec_command};

const MAX_TIMERS: usize = 1024;
const MAX_INVOKE_DEPTH: u32 = 16;
const STOP_PREFIX: &str = "\u{0}rux-stop:";

struct Timer {
    every: Option<Duration>,
    next: Instant,
    func: String,
    active: bool,
}

struct Normalized {
    name: String,
    ctx: Value,
    ev: Value,
}

struct TrackedCommand {
    pid: u32,
    detach: bool,
    frame: u32,
}

struct Runtime {
    handlers: Vec<(String, String)>,
    timers: Vec<Timer>,
    events: Mutex<Receiver<Value>>,
    stop: Option<i32>,
    invoke_depth: u32,
    at_top: bool,
    /// Commands spawned during this frame are stopped when the frame returns.
    frame: u32,
    next_frame: u32,
    commands: Vec<TrackedCommand>,
    session_id: Option<String>,
    block_id: Option<String>,
    client_id: Option<String>,
    args: Value,
    diagnostics: Vec<Value>,
    bindings: Vec<String>,
    api: ApiCall,
    actions: HashMap<String, String>,
    hosts: Vec<String>,
    host_endpoints: Vec<(String, Vec<String>)>,
}

pub struct ScriptRequest {
    pub name: String,
    pub source: String,
    pub session_id: Option<String>,
    pub block_id: Option<String>,
    pub client_id: Option<String>,
    pub args: Value,
    pub hosts: Vec<String>,
    pub host_endpoints: Vec<(String, Vec<String>)>,
}

pub struct ScriptResult {
    pub value: Value,
    pub code: i32,
    pub diagnostics: Vec<Value>,
    pub bindings: Vec<String>,
    pub kept_alive: bool,
}

/// Run one script to completion on this thread. `events` delivers server
/// events while it is blocked in `rex.wait`, `rex.sleep`, or a timer.
pub fn run_script(
    request: ScriptRequest,
    events: Receiver<Value>,
    api: ApiCall,
    on_loaded: Option<Sender<Result<ScriptResult, String>>>,
) -> Result<ScriptResult, String> {
    let lua = Lua::new();
    let runtime = Arc::new(Mutex::new(Runtime {
        handlers: Vec::new(),
        timers: Vec::new(),
        events: Mutex::new(events),
        stop: None,
        invoke_depth: 0,
        at_top: true,
        frame: 0,
        next_frame: 1,
        commands: Vec::new(),
        session_id: request.session_id,
        block_id: request.block_id,
        client_id: request.client_id,
        args: request.args,
        diagnostics: Vec::new(),
        bindings: Vec::new(),
        api,
        actions: HashMap::new(),
        hosts: request.hosts,
        host_endpoints: request.host_endpoints,
    }));
    install_script_api(&lua, &runtime).map_err(|error| error.to_string())?;
    disable_shell(&lua).map_err(|error| error.to_string())?;
    let loaded = lua
        .load(&request.source)
        .set_name(&request.name)
        .eval::<LuaValue>();
    {
        let mut runtime = runtime.lock().unwrap();
        runtime.at_top = false;
    }
    let value = match loaded {
        Ok(value) => lua.from_value::<Value>(value).unwrap_or(Value::Null),
        Err(error) => match stop_code(&error) {
            Some(code) => {
                let result = finish(&runtime, Value::Null, code, false)?;
                if let Some(on_loaded) = on_loaded {
                    let _ = on_loaded.send(Ok(clone_result(&result)));
                }
                return Ok(result);
            }
            None => {
                if let Some(on_loaded) = on_loaded {
                    let _ = on_loaded.send(Err(error.to_string()));
                }
                return Err(error.to_string());
            }
        },
    };
    if runtime.lock().unwrap().stop.is_some() {
        let code = runtime.lock().unwrap().stop.unwrap_or(0);
        reap_frame(&runtime, 0);
        let result = finish(&runtime, value, code, false)?;
        if let Some(on_loaded) = on_loaded {
            let _ = on_loaded.send(Ok(clone_result(&result)));
        }
        return Ok(result);
    }
    reap_frame(&runtime, 0);
    let kept_alive = {
        let runtime = runtime.lock().unwrap();
        !runtime.handlers.is_empty() || runtime.timers.iter().any(|timer| timer.active)
    };
    let loaded_result = finish(&runtime, value.clone(), 0, kept_alive)?;
    if let Some(on_loaded) = on_loaded {
        let _ = on_loaded.send(Ok(clone_result(&loaded_result)));
    }
    if !kept_alive {
        return Ok(loaded_result);
    }
    loop {
        if let Some(code) = runtime.lock().unwrap().stop {
            return finish(&runtime, value, code, false);
        }
        for event in pump(&lua, &runtime).map_err(|error| error.to_string())? {
            dispatch_handlers(&lua, &runtime, &event).map_err(|error| error.to_string())?;
        }
        let idle = {
            let runtime = runtime.lock().unwrap();
            runtime.handlers.is_empty()
                || runtime.stop.is_some() && runtime.timers.iter().all(|timer| !timer.active)
        };
        let runtime_ref = runtime.lock().unwrap();
        let alive = runtime_ref.stop.is_none()
            && (!runtime_ref.handlers.is_empty()
                || runtime_ref.timers.iter().any(|timer| timer.active));
        drop(runtime_ref);
        if !alive {
            let code = runtime.lock().unwrap().stop.unwrap_or(0);
            return finish(&runtime, value, code, false);
        }
        let _ = idle;
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn clone_result(result: &ScriptResult) -> ScriptResult {
    ScriptResult {
        value: result.value.clone(),
        code: result.code,
        diagnostics: result.diagnostics.clone(),
        bindings: result.bindings.clone(),
        kept_alive: result.kept_alive,
    }
}

fn finish(
    runtime: &Arc<Mutex<Runtime>>,
    value: Value,
    code: i32,
    kept_alive: bool,
) -> Result<ScriptResult, String> {
    let runtime = runtime.lock().unwrap();
    Ok(ScriptResult {
        value,
        code,
        diagnostics: runtime.diagnostics.clone(),
        bindings: runtime.bindings.clone(),
        kept_alive,
    })
}

fn stop_code(error: &mlua::Error) -> Option<i32> {
    let message = error.to_string();
    let rest = message.split(STOP_PREFIX).nth(1)?;
    let digits: String = rest
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit() || *ch == '-')
        .collect();
    digits.parse().ok()
}

/// Lua 5.1 compatibility prelude. Rex scripts target Lua 5.1; this
/// server runs Lua 5.4 through mlua. Restore the 5.1 names those
/// scripts reasonably rely on, each only when 5.4 lacks it. What is
/// shimmed, what 5.4 adds, and which deltas are left alone is written
/// up in spec/notes/lua-51-compat.md.
const LUA51_COMPAT: &str = r#"
unpack = unpack or table.unpack
loadstring = loadstring or load
if math.pow == nil then math.pow = function(x, y) return x ^ y end end
if math.atan2 == nil then math.atan2 = function(y, x) return math.atan(y, x) end end
if math.log10 == nil then math.log10 = function(x) return math.log(x, 10) end end
if math.ldexp == nil then math.ldexp = function(x, e) return x * (2 ^ e) end end
if math.frexp == nil then
  math.frexp = function(x)
    if x == 0 then return 0, 0 end
    local e = math.floor(math.log(math.abs(x), 2)) + 1
    local m = x / (2 ^ e)
    if m >= 1 then m = m / 2; e = e + 1
    elseif m < 0.5 then m = m * 2; e = e - 1 end
    return m, e
  end
end
if table.maxn == nil then
  table.maxn = function(t)
    local m = 0
    for k in pairs(t) do
      if type(k) == "number" and k > m then m = k end
    end
    return m
  end
end
if table.getn == nil then table.getn = function(t) return #t end end
if string.gfind == nil then string.gfind = string.gmatch end
if gcinfo == nil then gcinfo = function() return collectgarbage("count") end end
if package.loaders == nil and package.searchers ~= nil then
  package.loaders = package.searchers
end
if setfenv == nil and debug ~= nil and debug.getupvalue ~= nil
    and debug.setupvalue ~= nil and debug.getinfo ~= nil then
  local function env_slot(fn)
    local i = 1
    while true do
      local name = debug.getupvalue(fn, i)
      if name == nil then return nil end
      if name == "_ENV" then return i end
      i = i + 1
    end
  end
  local function resolve(fn)
    if type(fn) == "number" then
      local info = debug.getinfo(fn + 2, "f")
      return info and info.func or nil
    end
    return fn
  end
  getfenv = function(fn)
    local f = resolve(fn or 1)
    if f == nil then return nil end
    local slot = env_slot(f)
    if slot == nil then return nil end
    local _, env = debug.getupvalue(f, slot)
    return env
  end
  setfenv = function(fn, env)
    local f = resolve(fn)
    if f == nil then return nil end
    local slot = env_slot(f)
    if slot == nil then return nil end
    debug.setupvalue(f, slot, env)
    return f
  end
end
"#;

pub(crate) fn install_lua51_compat(lua: &Lua) -> mlua::Result<()> {
    lua.load(LUA51_COMPAT).set_name("lua51-compat").exec()
}

fn install_script_api(lua: &Lua, runtime: &Arc<Mutex<Runtime>>) -> mlua::Result<()> {
    install_lua51_compat(lua)?;
    let rex = lua.create_table()?;
    {
        let runtime = runtime.clone();
        rex.set(
            "on",
            lua.create_function_mut(move |lua, (event, func): (String, mlua::Function)| {
                let mut runtime = runtime.lock().unwrap();
                if !runtime.at_top {
                    return Err(mlua::Error::RuntimeError(
                        "rex.on is only available while a script is loading".into(),
                    ));
                }
                let id = stash(lua, "handler", func)?;
                runtime.handlers.push((event, id));
                Ok(())
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "wait",
            lua.create_function_mut(
                move |lua, (event, filter, timeout): (String, LuaValue, Option<LuaValue>)| {
                    let (filter, timeout) = normalize_wait_args(lua, filter, timeout)?;
                    wait_for(lua, &runtime, &event, filter, timeout)
                },
            )?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "sleep",
            lua.create_function_mut(move |lua, seconds: f64| {
                if !seconds.is_finite() || seconds < 0.0 {
                    return Err(mlua::Error::RuntimeError(
                        "rex.sleep: seconds must be a non-negative number".into(),
                    ));
                }
                let deadline = Instant::now() + Duration::from_secs_f64(seconds);
                while Instant::now() < deadline {
                    if let Some(code) = runtime.lock().unwrap().stop {
                        return Err(stop_error(code));
                    }
                    for event in pump(lua, &runtime)? {
                        dispatch_handlers(lua, &runtime, &event)?;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "stop",
            lua.create_function_mut(move |_, code: Option<i32>| {
                let code = code.unwrap_or(0);
                runtime.lock().unwrap().stop = Some(code);
                Err::<(), _>(stop_error(code))
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "exec",
            lua.create_function(move |lua, (argv, options): (Vec<String>, Option<Table>)| {
                let _ = &runtime;
                match exec_command(argv, options) {
                    Ok(result) => Ok((lua.to_value(&result)?, Option::<String>::None)),
                    Err(error) => Ok((LuaValue::Nil, Some(error))),
                }
            })?,
        )?;
    }
    rex.set("after", timer_ctor(lua, runtime, false)?)?;
    rex.set("every", timer_ctor(lua, runtime, true)?)?;
    install_exec_start_tracked(lua, &rex, Some(runtime))?;
    install_common(lua, runtime, &rex)?;
    install_script_surface(lua, runtime, &rex)?;
    lua.globals().set("rex", rex)?;
    Ok(())
}

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

fn install_script_surface(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    rex: &Table,
) -> mlua::Result<()> {
    {
        let runtime = runtime.clone();
        rex.set(
            "action",
            lua.create_function_mut(move |lua, definition: Table| {
                if !runtime.lock().unwrap().at_top {
                    return Err(mlua::Error::RuntimeError(
                        "rex.action is only available while a script is loading".into(),
                    ));
                }
                let name: String = definition.get("name")?;
                let title: String = definition.get("title")?;
                let run: mlua::Function = definition.get("run")?;
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
                let id = stash(lua, "action", run)?;
                let mut runtime = runtime.lock().unwrap();
                if runtime.actions.contains_key(&name) {
                    return Err(mlua::Error::RuntimeError(format!(
                        "rex.action: duplicate action {name}"
                    )));
                }
                runtime.actions.insert(name, id);
                Ok(())
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "invoke",
            lua.create_function(move |lua, (name, args): (String, Option<Table>)| {
                let args = table_to_json(lua, args)?;
                invoke_named(lua, &runtime, &name, args)
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "bind",
            lua.create_function_mut(
                move |_, (key, target, _args): (String, LuaValue, Option<LuaValue>)| {
                    let mut runtime = runtime.lock().unwrap();
                    if !runtime.at_top {
                        return Ok(());
                    }
                    if !matches!(target, LuaValue::Function(_)) {
                        return Ok(());
                    }
                    if key.contains('>') || key.contains('/') {
                        return Ok(());
                    }
                    if !key.is_empty() {
                        runtime.bindings.push(key);
                    }
                    Ok(())
                },
            )?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "unbind",
            lua.create_function_mut(move |_, _: LuaValue| {
                let _ = runtime.lock().unwrap().at_top;
                Ok(0)
            })?,
        )?;
    }
    for name in ["mode", "bindings", "modes"] {
        let runtime = runtime.clone();
        let label = name.to_string();
        rex.set(
            name,
            lua.create_function_mut(move |lua, _: LuaValue| {
                if !runtime.lock().unwrap().at_top {
                    return Err(mlua::Error::RuntimeError(format!(
                        "rex.{label} is only available while a script is loading"
                    )));
                }
                lua.create_table()
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "host",
            lua.create_function_mut(move |_, _: LuaValue| {
                if !runtime.lock().unwrap().at_top {
                    return Err(mlua::Error::RuntimeError(
                        "rex.host is only available while a script is loading".into(),
                    ));
                }
                Ok(())
            })?,
        )?;
    }
    let client = lua.create_table()?;
    {
        let runtime = runtime.clone();
        client.set(
            "queue",
            lua.create_function_mut(move |lua, (name, args): (String, Option<Table>)| {
                let (session_id, block_id) = {
                    let runtime = runtime.lock().unwrap();
                    if runtime.client_id.is_none() {
                        return Err(mlua::Error::RuntimeError(
                            "rex.client.queue: no client to ask".into(),
                        ));
                    }
                    (runtime.session_id.clone(), runtime.block_id.clone())
                };
                let args = table_to_json(lua, args)?;
                let mut payload = json!({ "action": name });
                if !args.is_null() {
                    payload["args"] = args;
                }
                if let Some(session_id) = session_id {
                    payload["session_id"] = json!(session_id);
                }
                if let Some(block_id) = block_id {
                    payload["block_id"] = json!(block_id);
                }
                let (_, error) = invoke_api(lua, &runtime, "rux.client_queue", payload)?;
                if let Some(error) = error {
                    return Err(mlua::Error::RuntimeError(error));
                }
                Ok(())
            })?,
        )?;
    }
    rex.set("client", client)?;
    Ok(())
}

fn invoke_named(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    name: &str,
    args: Value,
) -> mlua::Result<(LuaValue, Option<String>)> {
    let function_id = {
        let mut runtime = runtime.lock().unwrap();
        if runtime.invoke_depth >= MAX_INVOKE_DEPTH {
            return Ok((
                LuaValue::Nil,
                Some("rex.invoke nested too deep".to_string()),
            ));
        }
        runtime.invoke_depth += 1;
        runtime.actions.get(name).cloned()
    };
    let result = if let Some(function_id) = function_id {
        let func: mlua::Function = lua.named_registry_value(&function_id)?;
        let ctx = action_ctx(runtime);
        match func.call::<LuaValue>((lua.to_value(&ctx)?, lua.to_value(&args)?)) {
            Ok(value) => Ok((value, None)),
            Err(error) => {
                if stop_code(&error).is_some() {
                    let mut runtime = runtime.lock().unwrap();
                    runtime.invoke_depth = runtime.invoke_depth.saturating_sub(1);
                    return Err(error);
                }
                Ok((LuaValue::Nil, Some(error.to_string())))
            }
        }
    } else {
        let mut payload = json!({ "action": name, "args": args });
        fill_ids(runtime, &mut payload, true, false);
        invoke_api(lua, runtime, "client.action", payload)
    };
    {
        let mut runtime = runtime.lock().unwrap();
        runtime.invoke_depth = runtime.invoke_depth.saturating_sub(1);
    }
    result
}

fn action_ctx(runtime: &Arc<Mutex<Runtime>>) -> Value {
    let runtime = runtime.lock().unwrap();
    let mut ctx = json!({ "origin": "api" });
    if let Some(session_id) = &runtime.session_id {
        ctx["session_id"] = json!(session_id);
    }
    if let Some(block_id) = &runtime.block_id {
        ctx["block_id"] = json!(block_id);
    }
    if let Some(client_id) = &runtime.client_id {
        ctx["client_id"] = json!(client_id);
    }
    ctx
}

fn reap_frame(runtime: &Arc<Mutex<Runtime>>, frame: u32) {
    let pids: Vec<u32> = {
        let mut runtime = runtime.lock().unwrap();
        let mut pids = Vec::new();
        runtime.commands.retain(|command| {
            if command.frame == frame && !command.detach {
                pids.push(command.pid);
                false
            } else {
                true
            }
        });
        pids
    };
    for pid in pids {
        terminate_pid(pid, 15);
    }
}

fn enter_frame(runtime: &Arc<Mutex<Runtime>>) -> u32 {
    let mut runtime = runtime.lock().unwrap();
    let frame = runtime.next_frame;
    runtime.next_frame = runtime.next_frame.saturating_add(1);
    runtime.frame = frame;
    runtime.at_top = false;
    frame
}

fn timer_ctor(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    every: bool,
) -> mlua::Result<mlua::Function> {
    let runtime = runtime.clone();
    lua.create_function_mut(move |lua, (seconds, func): (f64, mlua::Function)| {
        if !seconds.is_finite() || seconds < 0.0 || (every && seconds == 0.0) {
            return Err(mlua::Error::RuntimeError(
                "timer interval must be a positive number".into(),
            ));
        }
        let handle_runtime = runtime.clone();
        let index = {
            let mut runtime = runtime.lock().unwrap();
            if runtime.timers.iter().filter(|timer| timer.active).count() >= MAX_TIMERS {
                runtime.stop = Some(1);
                return Err(stop_error(1));
            }
            let id = stash(lua, "timer", func)?;
            let interval = Duration::from_secs_f64(seconds);
            runtime.timers.push(Timer {
                every: every.then_some(interval),
                next: Instant::now() + interval,
                func: id,
                active: true,
            });
            runtime.timers.len() - 1
        };
        lua.create_userdata(TimerHandle {
            runtime: handle_runtime,
            index,
        })
    })
}

fn stash(lua: &Lua, prefix: &str, func: mlua::Function) -> mlua::Result<String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = format!(
        "{prefix}-{}",
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    lua.set_named_registry_value(&id, func)?;
    Ok(id)
}

fn stop_error(code: i32) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{STOP_PREFIX}{code}"))
}

struct TimerHandle {
    runtime: Arc<Mutex<Runtime>>,
    index: usize,
}

impl UserData for TimerHandle {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("cancel", |_lua, this, ()| {
            if let Some(timer) = this.runtime.lock().unwrap().timers.get_mut(this.index) {
                timer.active = false;
            }
            Ok(())
        });
        methods.add_method("active", |_lua, this, ()| {
            Ok(this
                .runtime
                .lock()
                .unwrap()
                .timers
                .get(this.index)
                .is_some_and(|timer| timer.active))
        });
    }
}

pub(crate) fn install_exec_start(lua: &Lua, rex: &Table) -> mlua::Result<()> {
    install_exec_start_tracked(lua, rex, None)
}

fn install_exec_start_tracked(
    lua: &Lua,
    rex: &Table,
    runtime: Option<&Arc<Mutex<Runtime>>>,
) -> mlua::Result<()> {
    let exec_fn: mlua::Function = rex.get("exec")?;
    let exec = lua.create_table()?;
    let tracked = runtime.cloned();
    let start =
        lua.create_function(move |lua, (argv, options): (Vec<String>, Option<Table>)| {
            match spawn_command(lua, argv, options) {
                Ok(spawned) => {
                    if let Some(runtime) = &tracked {
                        let mut runtime = runtime.lock().unwrap();
                        let frame = runtime.frame;
                        runtime.commands.push(TrackedCommand {
                            pid: spawned.pid,
                            detach: spawned.detach,
                            frame,
                        });
                    }
                    Ok((LuaValue::UserData(spawned.handle), Option::<String>::None))
                }
                Err(error) => Ok((LuaValue::Nil, Some(error))),
            }
        })?;
    exec.set("start", start)?;
    let wrapper = lua.create_function(
        move |_, (this, argv, options): (LuaValue, Vec<String>, Option<Table>)| {
            let _ = this;
            exec_fn.call::<(LuaValue, Option<String>)>((argv, options))
        },
    )?;
    let call = lua.create_table()?;
    call.set("__call", wrapper)?;
    exec.set_metatable(Some(call));
    rex.set("exec", exec)?;
    Ok(())
}

struct Spawned {
    handle: mlua::AnyUserData,
    pid: u32,
    detach: bool,
}

fn spawn_command(lua: &Lua, argv: Vec<String>, options: Option<Table>) -> Result<Spawned, String> {
    if argv.is_empty() {
        return Err("argv must contain a program".into());
    }
    warn_unknown_exec_options(options.as_ref());
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    let detach = options
        .as_ref()
        .and_then(|options| options.get::<Option<bool>>("detach").ok().flatten())
        .unwrap_or(false);
    let clear_env = options
        .as_ref()
        .and_then(|options| options.get::<Option<bool>>("clear_env").ok().flatten())
        .unwrap_or(false);
    if clear_env {
        command.env_clear();
    }
    if let Some(options) = &options
        && let Ok(Some(env)) = options.get::<Option<Table>>("env")
    {
        for pair in env.pairs::<String, LuaValue>() {
            let (key, value) = pair.map_err(|error| error.to_string())?;
            match value {
                LuaValue::String(value) => {
                    command.env(key, value.to_string_lossy().to_string());
                }
                LuaValue::Boolean(false) => {
                    command.env_remove(key);
                }
                _ => return Err(format!("env.{key} must be a string or false")),
            }
        }
    }
    let discard_stdout = options
        .as_ref()
        .and_then(|options| options.get::<LuaValue>("stdout").ok())
        .is_some_and(|value| matches!(value, LuaValue::Boolean(false)));
    let discard_stderr = options
        .as_ref()
        .and_then(|options| options.get::<LuaValue>("stderr").ok())
        .is_some_and(|value| matches!(value, LuaValue::Boolean(false)));
    let keep_stdin = options
        .as_ref()
        .and_then(|options| options.get::<LuaValue>("stdin").ok())
        .is_some_and(|value| matches!(value, LuaValue::Boolean(true) | LuaValue::String(_)));
    let stdin_text = options
        .as_ref()
        .and_then(|options| options.get::<Option<String>>("stdin").ok().flatten());
    if let Some(options) = &options
        && let Ok(Some(cwd)) = options.get::<Option<String>>("cwd")
    {
        command.current_dir(cwd);
    }
    command
        .stdin(if keep_stdin || stdin_text.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if discard_stdout {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(if discard_stderr {
            Stdio::null()
        } else {
            Stdio::piped()
        });
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let pid = child.id();
    let mut stdin = child.stdin.take();
    if let Some(text) = stdin_text
        && let Some(stream) = stdin.as_mut()
    {
        let _ = stream.write_all(text.as_bytes());
        stdin = None;
    }
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>)>();
    let stdout_tx = tx.clone();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || copy_stream(stdout, stdout_tx, true));
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || copy_stream(stderr, tx, false));
    }
    let stdout_fn = options
        .as_ref()
        .and_then(|options| options.get::<mlua::Function>("stdout").ok())
        .map(|func| lua.create_registry_value(func))
        .transpose()
        .map_err(|error| error.to_string())?;
    let stderr_fn = options
        .as_ref()
        .and_then(|options| options.get::<mlua::Function>("stderr").ok())
        .map(|func| lua.create_registry_value(func))
        .transpose()
        .map_err(|error| error.to_string())?;
    let handle = lua
        .create_userdata(CommandHandle {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            output: Mutex::new(rx),
            pid,
            stdout_fn,
            stderr_fn,
            stdout_buf: Mutex::new(Vec::new()),
            stderr_buf: Mutex::new(Vec::new()),
            done: Mutex::new(None),
        })
        .map_err(|error| error.to_string())?;
    Ok(Spawned {
        handle,
        pid,
        detach,
    })
}

fn warn_unknown_exec_options(options: Option<&Table>) {
    let Some(options) = options else {
        return;
    };
    const KNOWN: &[&str] = &[
        "cwd",
        "env",
        "clear_env",
        "stdin",
        "timeout",
        "stdout",
        "stderr",
        "text",
        "detach",
    ];
    let owned = options.clone();
    for pair in owned.pairs::<String, LuaValue>().flatten() {
        if !KNOWN.contains(&pair.0.as_str()) {
            tracing::warn!(target: "rux_lua", "rex.exec: ignoring unknown option {}", pair.0);
        }
    }
}

fn copy_stream<R: Read>(mut stream: R, tx: Sender<(bool, Vec<u8>)>, stdout: bool) {
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(size) => {
                if tx.send((stdout, chunk[..size].to_vec())).is_err() {
                    break;
                }
            }
        }
    }
}

struct CommandHandle {
    child: Mutex<Child>,
    stdin: Mutex<Option<std::process::ChildStdin>>,
    output: Mutex<Receiver<(bool, Vec<u8>)>>,
    pid: u32,
    stdout_fn: Option<RegistryKey>,
    stderr_fn: Option<RegistryKey>,
    stdout_buf: Mutex<Vec<u8>>,
    stderr_buf: Mutex<Vec<u8>>,
    done: Mutex<Option<Value>>,
}

impl UserData for CommandHandle {
    fn add_fields<F: mlua::UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("pid", |_, this| Ok(this.pid));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("running", |lua, this, ()| {
            deliver_output(lua, this)?;
            Ok(this
                .child
                .lock()
                .unwrap()
                .try_wait()
                .ok()
                .flatten()
                .is_none()
                && this.done.lock().unwrap().is_none())
        });
        methods.add_method("write", |_lua, this, data: String| {
            let mut stdin = this.stdin.lock().unwrap();
            let Some(stream) = stdin.as_mut() else {
                return Ok((LuaValue::Nil, Some("stdin is closed".to_string())));
            };
            match stream.write_all(data.as_bytes()) {
                Ok(()) => Ok((LuaValue::Boolean(true), Option::<String>::None)),
                Err(error) => Ok((LuaValue::Nil, Some(error.to_string()))),
            }
        });
        methods.add_method("close_stdin", |_lua, this, ()| {
            *this.stdin.lock().unwrap() = None;
            Ok(())
        });
        methods.add_method("kill", |_lua, this, signal: Option<LuaValue>| {
            let signal = match signal {
                Some(LuaValue::Integer(number)) => number as i32,
                Some(LuaValue::String(name)) => signal_number(&name.to_string_lossy()),
                _ => 15,
            };
            terminate_pid(this.pid, signal);
            Ok(())
        });
        methods.add_method("wait", |lua, this, seconds: Option<f64>| {
            let deadline = seconds
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .map(|seconds| Instant::now() + Duration::from_secs_f64(seconds));
            loop {
                deliver_output(lua, this)?;
                if let Some(result) = this.done.lock().unwrap().clone() {
                    return Ok((lua.to_value(&result)?, Option::<String>::None));
                }
                if let Some(status) = this
                    .child
                    .lock()
                    .unwrap()
                    .try_wait()
                    .map_err(|error| mlua::Error::external(error))?
                {
                    deliver_output(lua, this)?;
                    let result = exit_result(status, this);
                    *this.done.lock().unwrap() = Some(result.clone());
                    return Ok((lua.to_value(&result)?, Option::<String>::None));
                }
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Ok((LuaValue::Nil, Some("timeout".to_string())));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
    }
}

fn deliver_output(lua: &Lua, handle: &CommandHandle) -> mlua::Result<()> {
    let rx = handle.output.lock().unwrap();
    loop {
        match rx.try_recv() {
            Ok((stdout, bytes)) => {
                if stdout {
                    handle.stdout_buf.lock().unwrap().extend_from_slice(&bytes);
                } else {
                    handle.stderr_buf.lock().unwrap().extend_from_slice(&bytes);
                }
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let key = if stdout {
                    handle.stdout_fn.as_ref()
                } else {
                    handle.stderr_fn.as_ref()
                };
                if let Some(key) = key {
                    let func: mlua::Function = lua.registry_value(key)?;
                    func.call::<()>(text)?;
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
        }
    }
    Ok(())
}

fn exit_result(status: std::process::ExitStatus, handle: &CommandHandle) -> Value {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(signal_name)
    };
    #[cfg(not(unix))]
    let signal: Option<String> = None;
    let code = status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&handle.stdout_buf.lock().unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&handle.stderr_buf.lock().unwrap()).into_owned();
    json!({
        "code": code,
        "signal": signal,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": false,
        "ok": code == 0,
    })
}

fn signal_number(name: &str) -> i32 {
    match name {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGKILL" => 9,
        "SIGTERM" => 15,
        other => other
            .strip_prefix("SIG")
            .and_then(|number| number.parse().ok())
            .unwrap_or(15),
    }
}

fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        9 => "SIGKILL",
        15 => "SIGTERM",
        other => return format!("SIG{other}"),
    }
    .to_string()
}

fn terminate_pid(pid: u32, signal: i32) {
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        kill(pid as i32, signal);
    }
    #[cfg(not(unix))]
    let _ = (pid, signal);
}

fn install_session_helpers(
    lua: &Lua,
    parent: &Table,
    runtime: &Arc<Mutex<Runtime>>,
    fill: bool,
) -> mlua::Result<()> {
    install_session_helpers_to(lua, parent, runtime, fill, None)
}

fn install_session_helpers_to(
    lua: &Lua,
    parent: &Table,
    runtime: &Arc<Mutex<Runtime>>,
    fill: bool,
    endpoints: Option<Vec<String>>,
) -> mlua::Result<()> {
    let session = lua.create_table()?;
    for method in SESSION_METHODS {
        let runtime = runtime.clone();
        let endpoints = endpoints.clone();
        let method_name = format!("session.{method}");
        session.set(
            *method,
            lua.create_function_mut(move |lua, args: Option<Table>| {
                let mut payload = table_to_json(lua, args)?;
                if fill {
                    fill_ids(&runtime, &mut payload, true, false);
                }
                match &endpoints {
                    Some(endpoints) => {
                        crate::remote::invoke_lua(lua, endpoints, &method_name, payload)
                    }
                    None => invoke_api(lua, &runtime, &method_name, payload),
                }
            })?,
        )?;
    }
    parent.set("session", session)?;
    Ok(())
}

fn install_common(lua: &Lua, runtime: &Arc<Mutex<Runtime>>, rex: &Table) -> mlua::Result<()> {
    {
        let runtime = runtime.clone();
        let args = runtime.lock().unwrap().args.clone();
        rex.set("args", lua.to_value(&args)?)?;
        if let Some(session_id) = runtime.lock().unwrap().session_id.clone() {
            rex.set("session_id", session_id)?;
        }
        if let Some(block_id) = runtime.lock().unwrap().block_id.clone() {
            rex.set("block_id", block_id)?;
        }
        let _ = runtime;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "call",
            lua.create_function_mut(move |lua, (method, args): (String, Option<Table>)| {
                let mut payload = table_to_json(lua, args)?;
                fill_ids(&runtime, &mut payload, false, false);
                invoke_api(lua, &runtime, &method, payload)
            })?,
        )?;
    }
    install_session_helpers(lua, rex, runtime, true)?;
    let block = lua.create_table()?;
    {
        let runtime = runtime.clone();
        block.set(
            "call",
            lua.create_function_mut(
                move |lua, (creator, method, args): (String, String, Option<Table>)| {
                    let args = table_to_json(lua, args)?;
                    let mut payload = json!({ "method": method, "args": args });
                    fill_ids(&runtime, &mut payload, true, true);
                    if payload.get("block_id").is_none() {
                        return Ok((LuaValue::Nil, Some("block_id is required".to_string())));
                    }
                    let _ = creator;
                    invoke_api(lua, &runtime, "block.method", payload)
                },
            )?,
        )?;
    }
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
    {
        let runtime = runtime.clone();
        rex.set(
            "servers",
            lua.create_function(move |lua, ()| {
                let labels = runtime.lock().unwrap().hosts.clone();
                lua.to_value(&labels)
            })?,
        )?;
    }
    {
        let runtime = runtime.clone();
        rex.set(
            "server",
            lua.create_function_mut(move |lua, label: String| {
                if !runtime
                    .lock()
                    .unwrap()
                    .hosts
                    .iter()
                    .any(|host| host == &label)
                {
                    return Err(mlua::Error::RuntimeError(format!("unknown server {label}")));
                }
                let endpoints = runtime
                    .lock()
                    .unwrap()
                    .host_endpoints
                    .iter()
                    .find(|(host_label, _)| host_label == &label)
                    .map(|(_, endpoints)| endpoints.clone())
                    .filter(|endpoints| !endpoints.is_empty());
                let proxy = lua.create_table()?;
                install_session_helpers_to(lua, &proxy, &runtime, false, endpoints.clone())?;
                let call_runtime = runtime.clone();
                let call_endpoints = endpoints.clone();
                proxy.set(
                    "call",
                    lua.create_function_mut(
                        move |lua, (method, args): (String, Option<Table>)| {
                            let payload = table_to_json(lua, args)?;
                            match &call_endpoints {
                                Some(endpoints) => {
                                    crate::remote::invoke_lua(lua, endpoints, &method, payload)
                                }
                                None => invoke_api(lua, &call_runtime, &method, payload),
                            }
                        },
                    )?,
                )?;
                let block_runtime = runtime.clone();
                let block_endpoints = endpoints.clone();
                let block = lua.create_table()?;
                block.set(
                    "call",
                    lua.create_function_mut(
                        move |lua, (creator, method, args): (String, String, Option<Table>)| {
                            let _ = creator;
                            let args = table_to_json(lua, args)?;
                            let mut payload = json!({ "method": method, "args": args });
                            if let Some(block_id) = args.get("block_id").cloned() {
                                payload["block_id"] = block_id;
                            }
                            if let Some(session_id) = args.get("session_id").cloned() {
                                payload["session_id"] = session_id;
                            }
                            if payload.get("block_id").is_none() {
                                return Ok((
                                    LuaValue::Nil,
                                    Some("block_id is required".to_string()),
                                ));
                            }
                            match &block_endpoints {
                                Some(endpoints) => crate::remote::invoke_lua(
                                    lua,
                                    endpoints,
                                    "block.method",
                                    payload,
                                ),
                                None => invoke_api(lua, &block_runtime, "block.method", payload),
                            }
                        },
                    )?,
                )?;
                proxy.set("block", block)?;
                Ok(proxy)
            })?,
        )?;
    }
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
                Ok(value) => Ok((
                    lua.to_value(&crate::config::json_for_lua(value))?,
                    Option::<String>::None,
                )),
                Err(error) => Ok((LuaValue::Nil, Some(error.to_string()))),
            },
        )?,
    )?;
    rex.set("json", json_api)?;
    rex.set(
        "log",
        lua.create_function(|_, args: mlua::MultiValue| {
            let level = if args.len() >= 2 {
                lua_string(&args[0])
            } else {
                "info".to_string()
            };
            let message = if args.len() >= 2 {
                lua_string(&args[1])
            } else if args.len() == 1 {
                lua_string(&args[0])
            } else {
                String::new()
            };
            match level.as_str() {
                "debug" => tracing::debug!(target: "rux_lua", "{message}"),
                "warn" => tracing::warn!(target: "rux_lua", "{message}"),
                "error" => tracing::error!(target: "rux_lua", "{message}"),
                _ => tracing::info!(target: "rux_lua", "{message}"),
            }
            eprintln!("{message}");
            Ok(())
        })?,
    )?;
    Ok(())
}

fn fill_ids(
    runtime: &Arc<Mutex<Runtime>>,
    payload: &mut Value,
    fill_session: bool,
    fill_block: bool,
) {
    if !payload.is_object() {
        *payload = json!({});
    }
    let runtime = runtime.lock().unwrap();
    if fill_session
        && payload.get("session_id").is_none()
        && let Some(session_id) = &runtime.session_id
    {
        payload["session_id"] = json!(session_id);
    }
    if fill_block
        && payload.get("block_id").is_none()
        && let Some(block_id) = &runtime.block_id
    {
        payload["block_id"] = json!(block_id);
    }
}

fn invoke_api(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    method: &str,
    payload: Value,
) -> mlua::Result<(LuaValue, Option<String>)> {
    let api = runtime.lock().unwrap().api.clone();
    match api(method.to_string(), payload) {
        Ok(result) => Ok((lua.to_value(&result)?, None)),
        Err(error) => Ok((LuaValue::Nil, Some(error))),
    }
}

fn table_to_json(lua: &Lua, table: Option<Table>) -> mlua::Result<Value> {
    match table {
        Some(table) => lua.from_value(LuaValue::Table(table)),
        None => Ok(json!({})),
    }
}

fn normalize_wait_args(
    lua: &Lua,
    filter: LuaValue,
    timeout: Option<LuaValue>,
) -> mlua::Result<(LuaValue, Option<f64>)> {
    match (&filter, timeout) {
        (LuaValue::Nil, None) | (LuaValue::Nil, Some(LuaValue::Nil)) => Ok((LuaValue::Nil, None)),
        (LuaValue::Number(number), None) => Ok((LuaValue::Nil, Some(*number))),
        (LuaValue::Integer(number), None) => Ok((LuaValue::Nil, Some(*number as f64))),
        (filter, Some(LuaValue::Number(number))) => Ok((filter.clone(), Some(number))),
        (filter, Some(LuaValue::Integer(number))) => Ok((filter.clone(), Some(number as f64))),
        (filter, None) | (filter, Some(LuaValue::Nil)) => Ok((filter.clone(), None)),
        _ => Err(mlua::Error::RuntimeError(
            "rex.wait: timeout must be a number".into(),
        )),
    }
    .map(|(filter, timeout)| {
        let _ = lua;
        (filter, timeout)
    })
}

fn lua_string(value: &LuaValue) -> String {
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

fn wait_for(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    event: &str,
    filter: LuaValue,
    timeout: Option<f64>,
) -> mlua::Result<(LuaValue, LuaValue)> {
    let deadline = timeout
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .map(|seconds| Instant::now() + Duration::from_secs_f64(seconds));
    loop {
        if let Some(code) = runtime.lock().unwrap().stop {
            return Err(stop_error(code));
        }
        for normalized in pump(lua, runtime)? {
            dispatch_handlers(lua, runtime, &normalized)?;
            if normalized.name == event
                && filter_matches(lua, &filter, &normalized.ev, &normalized.ctx)?
            {
                return Ok((
                    lua.to_value(&normalized.ev)?,
                    lua.to_value(&normalized.ctx)?,
                ));
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok((LuaValue::Nil, lua.to_value(&"timeout")?));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn filter_matches(lua: &Lua, filter: &LuaValue, ev: &Value, ctx: &Value) -> mlua::Result<bool> {
    match filter {
        LuaValue::Nil => Ok(true),
        LuaValue::Function(func) => {
            let matched: LuaValue = func.call((lua.to_value(ev)?, lua.to_value(ctx)?))?;
            Ok(matches!(matched, LuaValue::Boolean(true)))
        }
        LuaValue::Table(filter) => {
            let filter: Value = lua.from_value(LuaValue::Table(filter.clone()))?;
            let Some(filter) = filter.as_object() else {
                return Ok(true);
            };
            Ok(filter
                .iter()
                .all(|(key, expected)| ev.get(key) == Some(expected)))
        }
        _ => Ok(true),
    }
}

fn pump(lua: &Lua, runtime: &Arc<Mutex<Runtime>>) -> mlua::Result<Vec<Normalized>> {
    fire_timers(lua, runtime)?;
    let events = {
        let runtime = runtime.lock().unwrap();
        let rx = runtime.events.lock().unwrap();
        let mut events = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        events
    };
    Ok(events.into_iter().filter_map(normalize_event).collect())
}

fn fire_timers(lua: &Lua, runtime: &Arc<Mutex<Runtime>>) -> mlua::Result<()> {
    let due: Vec<(usize, String, bool, Duration)> = {
        let runtime = runtime.lock().unwrap();
        runtime
            .timers
            .iter()
            .enumerate()
            .filter(|(_, timer)| timer.active && timer.next <= Instant::now())
            .map(|(index, timer)| {
                (
                    index,
                    timer.func.clone(),
                    timer.every.is_some(),
                    timer.every.unwrap_or_default(),
                )
            })
            .collect()
    };
    for (index, key, repeating, interval) in due {
        {
            let mut runtime = runtime.lock().unwrap();
            let Some(timer) = runtime.timers.get_mut(index) else {
                continue;
            };
            if !timer.active {
                continue;
            }
            if repeating {
                timer.next = Instant::now() + interval;
            } else {
                timer.active = false;
            }
            runtime.at_top = false;
        }
        let frame = enter_frame(runtime);
        let func: mlua::Function = lua.named_registry_value(&key)?;
        let ctx = json!({ "origin": "timer" });
        let called = func.call::<LuaValue>(lua.to_value(&ctx)?);
        reap_frame(runtime, frame);
        if let Err(error) = called {
            if stop_code(&error).is_some() {
                return Err(error);
            }
            runtime.lock().unwrap().diagnostics.push(json!({
                "severity": "error",
                "message": error.to_string(),
            }));
        }
    }
    Ok(())
}

fn dispatch_handlers(
    lua: &Lua,
    runtime: &Arc<Mutex<Runtime>>,
    event: &Normalized,
) -> mlua::Result<()> {
    let handlers: Vec<String> = runtime
        .lock()
        .unwrap()
        .handlers
        .iter()
        .filter(|(name, _)| {
            name == &event.name
                || name
                    == &format!(
                        "com.superlogical.terminal.{}",
                        event.name.trim_start_matches("terminal.")
                    )
        })
        .map(|(_, key)| key.clone())
        .collect();
    for key in handlers {
        let func: mlua::Function = lua.named_registry_value(&key)?;
        let ctx = lua.to_value(&event.ctx)?;
        let ev = lua.to_value(&event.ev)?;
        let frame = enter_frame(runtime);
        let called = func.call::<()>((ctx, ev));
        reap_frame(runtime, frame);
        if let Err(error) = called {
            if stop_code(&error).is_some() {
                runtime.lock().unwrap().stop = stop_code(&error);
                return Err(error);
            }
            runtime.lock().unwrap().diagnostics.push(json!({
                "severity": "error",
                "message": error.to_string(),
            }));
        }
    }
    Ok(())
}

fn normalize_event(event: Value) -> Option<Normalized> {
    if let Some(name) = event.get("name").and_then(Value::as_str) {
        return Some(Normalized {
            name: name.to_string(),
            ctx: event.get("ctx").cloned().unwrap_or_else(|| json!({})),
            ev: event.get("ev").cloned().unwrap_or_else(|| json!({})),
        });
    }
    let kind = event.get("type").and_then(Value::as_str)?;
    if kind == "session_event" {
        let payload = event.get("payload")?;
        let session_id = payload.get("session_id").cloned().unwrap_or(Value::Null);
        let inner = payload.get("event")?;
        let inner_kind = inner.get("type").and_then(Value::as_str).unwrap_or("");
        if inner_kind == "block_event" {
            let body = inner.get("payload")?;
            let creator = body
                .get("creator_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let name = body.get("name").and_then(Value::as_str).unwrap_or("");
            let lua_name = if creator == "com.superlogical.terminal" {
                format!("terminal.{name}")
            } else if creator.is_empty() {
                name.to_string()
            } else {
                format!("{creator}.{name}")
            };
            let mut ctx = json!({ "session_id": session_id });
            if let Some(block_id) = body.get("block_id") {
                ctx["block_id"] = block_id.clone();
            }
            return Some(Normalized {
                name: lua_name,
                ctx,
                ev: body.get("payload").cloned().unwrap_or_else(|| json!({})),
            });
        }
        return Some(Normalized {
            name: inner_kind.to_string(),
            ctx: json!({ "session_id": session_id }),
            ev: inner.get("payload").cloned().unwrap_or_else(|| json!({})),
        });
    }
    Some(Normalized {
        name: kind.to_string(),
        ctx: json!({}),
        ev: event.get("payload").cloned().unwrap_or_else(|| json!({})),
    })
}

fn disable_shell(lua: &Lua) -> mlua::Result<()> {
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
    Ok(())
}

/// Split the config's host declarations into the labels `rex.servers`
/// returns and the endpoints `rex.server` forwards to.
pub fn host_labels_and_endpoints(
    hosts: &[Value],
) -> (Vec<String>, Vec<(String, Vec<String>)>) {
    let mut labels = Vec::new();
    let mut endpoints = Vec::new();
    for host in hosts {
        let Some(label) = host.get("label").and_then(Value::as_str) else {
            continue;
        };
        labels.push(label.to_string());
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
        endpoints.push((label.to_string(), list));
    }
    (labels, endpoints)
}

/// Start a client script bundle. The load must finish within 5 seconds.
/// Handlers keep a thread alive afterwards; `events` is how the server feeds it.
pub fn start_client_scripts(
    scripts: Vec<(String, String)>,
    session_id: Option<String>,
    client_id: Option<String>,
    hosts: Vec<String>,
    host_endpoints: Vec<(String, Vec<String>)>,
    events: Receiver<Value>,
    api: ApiCall,
) -> Result<(ScriptResult, Option<JoinHandle<()>>), String> {
    let (done_tx, done_rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = std::thread::spawn(move || {
        let source = scripts
            .iter()
            .map(|(_, source)| source.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let name = scripts
            .first()
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| "script.lua".into());
        let _ = run_script(
            ScriptRequest {
                name,
                source,
                session_id,
                block_id: None,
                client_id,
                args: json!({}),
                hosts,
                host_endpoints,
            },
            events,
            api,
            Some(done_tx),
        );
    });
    match done_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(result)) => Ok((result, Some(worker))),
        Ok(Err(error)) => Err(error),
        Err(_) => {
            stop.store(true, Ordering::SeqCst);
            Err("script load exceeded 5 seconds".into())
        }
    }
}

pub fn run_do(
    source: &str,
    name: &str,
    session_id: Option<String>,
    block_id: Option<String>,
    args: Value,
    api: ApiCall,
) -> Result<ScriptResult, String> {
    let (_tx, rx) = mpsc::channel();
    run_script(
        ScriptRequest {
            name: name.to_string(),
            source: source.to_string(),
            session_id,
            block_id,
            client_id: None,
            args,
            hosts: Vec::new(),
            host_endpoints: Vec::new(),
        },
        rx,
        api,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_ok() -> ApiCall {
        Arc::new(|method, payload| Ok(json!({ "method": method, "payload": payload })))
    }

    #[test]
    fn sleep_json_log_and_ids_match_the_script_page() {
        let result = run_do(
            r#"
            rex.sleep(0.01)
            rex.log("warn", "hello")
            local text, err = rex.json.encode({ a = 1 }, { indent = true })
            assert(err == nil)
            assert(text:find("\n"))
            local bad, why = rex.json.encode(function() end)
            assert(bad == nil and why)
            local decoded = rex.json.decode('{"n":1}')
            assert(decoded.n == 1)
            local nope, why2 = rex.json.decode("{")
            assert(nope == nil and why2)
            return rex.session_id .. ":" .. rex.args.name
            "#,
            "ids.lua",
            Some("session:1".into()),
            None,
            json!({ "name": "rex" }),
            api_ok(),
        )
        .unwrap();
        assert_eq!(result.value, json!("session:1:rex"));
        assert_eq!(result.code, 0);
    }

    #[test]
    fn wait_returns_the_event_or_timeout() {
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            tx.send(json!({
                "name": "terminal.bell",
                "ctx": { "session_id": "session:1" },
                "ev": {}
            }))
            .unwrap();
        });
        let lua = Lua::new();
        let runtime = Arc::new(Mutex::new(Runtime {
            handlers: Vec::new(),
            timers: Vec::new(),
            events: Mutex::new(rx),
            stop: None,
            invoke_depth: 0,
            at_top: true,
            frame: 0,
            next_frame: 1,
            commands: Vec::new(),
            session_id: None,
            block_id: None,
            client_id: None,
            args: json!({}),
            diagnostics: Vec::new(),
            bindings: Vec::new(),
            api: api_ok(),
            actions: HashMap::new(),
            hosts: Vec::new(),
            host_endpoints: Vec::new(),
        }));
        install_script_api(&lua, &runtime).unwrap();
        let value: LuaValue = lua
            .load(
                r#"
                local ev, ctx = rex.wait("terminal.bell", 1)
                return ctx.session_id
                "#,
            )
            .set_name("wait.lua")
            .eval()
            .unwrap();
        assert_eq!(value.to_string().unwrap_or_default(), "session:1");
        worker.join().unwrap();
        let late = lua
            .load(r#"local ev, err = rex.wait("terminal.bell", 0.05); return err"#)
            .eval::<LuaValue>()
            .unwrap();
        assert_eq!(late.to_string().unwrap_or_default(), "timeout");
    }

    #[test]
    fn lua51_compat_shims_restore_the_51_surface() {
        let lua = Lua::new();
        install_lua51_compat(&lua).unwrap();
        let num = |src: &str| -> f64 {
            lua.load(src).eval::<f64>().unwrap_or_else(|e| panic!("{src}: {e}"))
        };
        // Globals and library names removed after 5.1.
        assert_eq!(num("local a, b, c = unpack({10, 20, 30}); return a + b + c"), 60.0);
        assert_eq!(num("return loadstring('return 6 * 7')()"), 42.0);
        assert_eq!(num("return math.pow(2, 10)"), 1024.0);
        assert!((num("return math.log10(1000)") - 3.0).abs() < 1e-9);
        assert!((num("return math.atan2(1, 1)") - std::f64::consts::FRAC_PI_4).abs() < 1e-12);
        assert_eq!(num("return math.ldexp(0.5, 4)"), 8.0);
        assert_eq!(num("local m, e = math.frexp(8); return m * 100 + e"), 54.0);
        assert_eq!(num("local t = {}; t[7] = true; return table.maxn(t)"), 7.0);
        assert_eq!(num("return table.getn({1, 2, 3})"), 3.0);
        assert_eq!(
            num("local s = 0; for d in string.gfind('a1b22', '%d+') do s = s + tonumber(d) end; return s"),
            23.0
        );
        let text = |src: &str| -> String { lua.load(src).eval::<String>().unwrap() };
        assert_eq!(text("return type(gcinfo())"), "number");
        assert_eq!(text("return type(package.loaders)"), "table");
        // Function environments: the function form replaces the
        // function's _ENV upvalue, the level form targets the caller.
        assert_eq!(
            num("local env = { x = 42 }; local f = function() return x end;                  setfenv(f, env); return f() + getfenv(f).x"),
            84.0
        );
        assert_eq!(
            num("local env = { z = 99 }; local function f() setfenv(1, env); return z end; return f()"),
            99.0
        );
    }

    #[test]
    fn exec_start_writes_and_kills() {
        let result = run_do(
            r#"
            local h, err = rex.exec.start({"cat"}, { stdin = true })
            assert(h, err)
            assert(h:running())
            assert(h:write("hello\n"))
            h:close_stdin()
            local done = h:wait(2)
            assert(done.ok, done.code)
            assert(done.stdout == "hello\n", done.stdout)
            local sleeper = rex.exec.start({"sleep", "30"})
            sleeper:kill("SIGTERM")
            local stopped = sleeper:wait(2)
            assert(stopped.signal == "SIGTERM")
            return done.code
            "#,
            "exec.lua",
            None,
            None,
            json!({}),
            api_ok(),
        )
        .unwrap();
        assert_eq!(result.value, json!(0));
    }

    #[test]
    fn timers_fire_and_the_cap_stops_the_script() {
        let result = run_do(
            r#"
            local n = 0
            rex.after(0.01, function() n = n + 1 end)
            rex.sleep(0.05)
            assert(n == 1)
            return n
            "#,
            "timer.lua",
            None,
            None,
            json!({}),
            api_ok(),
        )
        .unwrap();
        assert_eq!(result.value, json!(1));

        let capped = run_do(
            &format!(
                "for i = 1, {} do rex.after(10, function() end) end return 0",
                MAX_TIMERS + 1
            ),
            "cap.lua",
            None,
            None,
            json!({}),
            api_ok(),
        )
        .unwrap();
        assert_eq!(capped.code, 1);
    }

    #[test]
    fn on_handler_sees_a_wrapped_block_event() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            tx.send(json!({
                "type": "session_event",
                "payload": {
                    "session_id": "session:9",
                    "event": {
                        "type": "block_event",
                        "payload": {
                            "block_id": "block:9",
                            "creator_name": "com.superlogical.terminal",
                            "name": "bell",
                            "payload": {}
                        }
                    }
                }
            }))
            .unwrap();
        });
        let result = run_script(
            ScriptRequest {
                name: "on.lua".into(),
                source: r#"
                    rex.on("terminal.bell", function(ctx, ev)
                        rex.stop(7)
                    end)
                    rex.sleep(1)
                "#
                .into(),
                session_id: None,
                block_id: None,
                client_id: None,
                args: json!({}),
                hosts: Vec::new(),
                host_endpoints: Vec::new(),
            },
            rx,
            api_ok(),
            None,
        )
        .unwrap();
        assert_eq!(result.code, 7);
    }

    #[test]
    fn script_surface_matches_the_lua_page() {
        let result = run_script(
            ScriptRequest {
                name: "surface.lua".into(),
                source: r#"
                    rex.action{ name = "greet", title = "Greet", run = function(ctx, args)
                        return (args.name or "") .. "@" .. (ctx.session_id or "")
                    end }
                    local greeted = rex.invoke("greet", { name = "rex" })
                    local layout = rex.layout.horizontal(0.5, rex.layout.block{ flavor = "shell" }, rex.layout.vertical(0.25, { marker = true }, { marker = false }))
                    local echoed = rex.session.set_block_label{ label = "tests" }
                    rex.bind("ctrl+g", function() return true end)
                    rex.bind("ctrl+a>b", function() end)
                    local listed = rex.servers()
                    local remote = rex.server("other")
                    local forwarded = remote.call("session.list")
                    local missing = pcall(function() rex.server("nope") end)
                    return {
                        greeted = greeted,
                        direction = layout.split.direction,
                        session_id = echoed.payload.session_id,
                        block_filled = echoed.payload.block_id ~= nil,
                        hosts = listed[1],
                        remote_session = forwarded.payload.session_id,
                        missing = missing,
                    }
                "#
                .into(),
                session_id: Some("session:1".into()),
                block_id: Some("block:1".into()),
                client_id: Some("client:1".into()),
                args: json!({}),
                hosts: vec!["other".into()],
                host_endpoints: Vec::new(),
            },
            mpsc::channel().1,
            api_ok(),
            None,
        )
        .unwrap();
        assert_eq!(result.value["greeted"], json!("rex@session:1"));
        assert_eq!(result.value["direction"], json!("horizontal"));
        assert_eq!(result.value["session_id"], json!("session:1"));
        assert_eq!(result.value["block_filled"], json!(false));
        assert_eq!(result.value["hosts"], json!("other"));
        assert!(result.value["remote_session"].is_null());
        assert_eq!(result.value["missing"], json!(false));
        assert_eq!(result.bindings, vec!["ctrl+g".to_string()]);

        let queued = run_script(
            ScriptRequest {
                name: "queue.lua".into(),
                source: r#"rex.client.queue("pane.zoom", { on = true }); return true"#.into(),
                session_id: None,
                block_id: None,
                client_id: Some("client:1".into()),
                args: json!({}),
                hosts: Vec::new(),
                host_endpoints: Vec::new(),
            },
            mpsc::channel().1,
            api_ok(),
            None,
        )
        .unwrap();
        assert_eq!(queued.value, json!(true));

        let no_client = run_do(
            r#"rex.client.queue("pane.zoom")"#,
            "queue.lua",
            None,
            None,
            json!({}),
            api_ok(),
        );
        assert!(no_client.is_err());

        let deep = run_do(
            r#"
            rex.action{ name = "nest", title = "Nest", run = function()
                local value, err = rex.invoke("nest")
                if err ~= nil then error(err, 0) end
                return value
            end }
            local value, err = rex.invoke("nest")
            return err
            "#,
            "nest.lua",
            None,
            None,
            json!({}),
            api_ok(),
        )
        .unwrap();
        assert!(
            deep.value
                .as_str()
                .is_some_and(|message| message.contains("rex.invoke nested too deep")),
            "{:?}",
            deep.value
        );
    }

    #[test]
    fn rex_server_forwards_to_the_hosts_endpoint() {
        let path =
            std::env::temp_dir().join(format!("rux-remote-{}.sock", uuid::Uuid::now_v7()));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept_hdr(
                stream,
                |_request: &tungstenite::handshake::server::Request,
                 mut response: tungstenite::handshake::server::Response|
                 -> Result<
                    tungstenite::handshake::server::Response,
                    tungstenite::handshake::server::ErrorResponse,
                > {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        tungstenite::http::HeaderValue::from_static("rex.control.v1"),
                    );
                    Ok(response)
                },
            )
            .unwrap();
            let hello = socket.read().unwrap().to_string();
            assert!(hello.contains("\"hello\""), "{hello}");
            socket
                .write(tungstenite::Message::Text(
                    "{\"type\":\"welcome\",\"protocol\":\"rex.control.v1\"}".into(),
                ))
                .unwrap();
            socket.flush().unwrap();
            let request = socket.read().unwrap().to_string();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["method"], "server.version");
            let id = request["id"].as_str().unwrap().to_string();
            socket
                .write(tungstenite::Message::Text(
                    json!({
                        "type": "response",
                        "id": id,
                        "seq": 1,
                        "payload": { "version": "stub-9" },
                    })
                    .to_string()
                    .into(),
                ))
                .unwrap();
            socket.flush().unwrap();
        });
        let result = run_script(
            ScriptRequest {
                name: "remote.lua".into(),
                source: r#"
                    local remote = rex.server("other")
                    local version, err = remote.call("server.version")
                    if err then error(err, 0) end
                    return version.version
                "#
                .into(),
                session_id: None,
                block_id: None,
                client_id: None,
                args: json!({}),
                hosts: vec!["other".into()],
                host_endpoints: vec![(
                    "other".into(),
                    vec![format!("unix://{}", path.display())],
                )],
            },
            mpsc::channel().1,
            api_ok(),
            None,
        )
        .unwrap();
        assert_eq!(result.value, json!("stub-9"));
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }
}
