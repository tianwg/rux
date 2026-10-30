//! Login-server accounts file and who may use which OS account.
//!
//! `/etc/rex/accounts.jsonc` is JSON with comments and trailing commas. The
//! login server uses this to pick an account before PAM runs.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accounts {
    pub version: u64,
    pub accounts: Vec<(String, Vec<String>)>,
    pub defaults: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Caller {
    pub tailscale_login: Option<String>,
    pub tags: Vec<String>,
    pub uid: Option<u32>,
    pub identified: bool,
    pub anonymous: bool,
}

#[derive(Clone, Debug)]
pub struct OsUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub locked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SelectError {
    Parse(String),
    Denied(String),
    Ambiguous,
    Policy(String),
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectError::Parse(message)
            | SelectError::Denied(message)
            | SelectError::Policy(message) => {
                write!(f, "{message}")
            }
            SelectError::Ambiguous => write!(f, "name the account in the server address"),
        }
    }
}

pub fn parse_accounts(text: &str) -> Result<Accounts, SelectError> {
    let json = strip_jsonc(text);
    let value: Value =
        serde_json::from_str(&json).map_err(|error| SelectError::Parse(error.to_string()))?;
    let version = value.get("version").and_then(Value::as_u64).unwrap_or(1);
    let mut accounts = Vec::new();
    if let Some(map) = value.get("accounts").and_then(Value::as_object) {
        for (name, spec) in map {
            let principals = spec
                .get("principals")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if name == "*" && principals.iter().any(|principal| principal == "anonymous") {
                return Err(SelectError::Parse(
                    "anonymous is forbidden under \"*\"".into(),
                ));
            }
            accounts.push((name.clone(), principals));
        }
    }
    let defaults = value
        .get("defaults")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(principal, account)| {
                    account
                        .as_str()
                        .map(|account| (principal.clone(), account.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    // serde_json::Map is a BTreeMap, so re-read defaults in file order.
    let defaults = ordered_object_pairs(&json, "defaults").unwrap_or(defaults);
    let accounts = ordered_accounts(&json).unwrap_or(accounts);
    Ok(Accounts {
        version,
        accounts,
        defaults,
    })
}

pub fn select_account(
    accounts: &Accounts,
    caller: &Caller,
    requested: Option<&str>,
    users: &[OsUser],
) -> Result<String, SelectError> {
    if caller.anonymous && requested == Some("root") {
        return Err(SelectError::Denied(
            "anonymous callers cannot use root".into(),
        ));
    }
    let allowed = allowed_names(accounts, caller, users);
    let chosen = if let Some(name) = requested {
        if !allowed.iter().any(|account| account == name) {
            return Err(SelectError::Denied(format!(
                "not allowed to use account {name}"
            )));
        }
        name.to_string()
    } else if let Some(name) = default_account(accounts, caller) {
        if !allowed.iter().any(|account| account == &name) {
            return Err(SelectError::Denied(format!(
                "default account {name} is not allowed"
            )));
        }
        name
    } else if allowed.len() == 1 {
        allowed[0].clone()
    } else if allowed.is_empty() {
        return Err(SelectError::Denied("no account is allowed".into()));
    } else {
        return Err(SelectError::Ambiguous);
    };
    if let Some(user) = users.iter().find(|user| user.name == chosen) {
        may_login(user, caller)?;
    }
    Ok(chosen)
}

pub fn may_login(user: &OsUser, caller: &Caller) -> Result<(), SelectError> {
    if caller.anonymous && (user.uid == 0 || user.name == "root") {
        return Err(SelectError::Denied(
            "anonymous callers cannot use root".into(),
        ));
    }
    let shell = user.shell.rsplit('/').next().unwrap_or("");
    if shell == "nologin" || shell == "false" {
        return Err(SelectError::Policy(format!(
            "account {} has a nologin shell",
            user.name
        )));
    }
    if user.locked {
        return Err(SelectError::Policy(format!(
            "account {} is locked",
            user.name
        )));
    }
    Ok(())
}

/// `/etc/nologin` blocks everyone except root. Nologin shells are always
/// refused. A shadow lock is the `--pam=false` policy; with PAM on, the
/// login-session supervisor asks PAM instead.
pub fn policy_from_files(
    user: &OsUser,
    nologin_exists: bool,
    pam: bool,
) -> Result<(), SelectError> {
    if nologin_exists && user.uid != 0 {
        return Err(SelectError::Policy(
            "/etc/nologin is present; only root may log in".into(),
        ));
    }
    let shell = user.shell.rsplit('/').next().unwrap_or("");
    if shell == "nologin" || shell == "false" {
        return Err(SelectError::Policy(format!(
            "account {} has a nologin shell",
            user.name
        )));
    }
    if !pam && user.locked {
        return Err(SelectError::Policy(format!(
            "account {} is locked in /etc/shadow",
            user.name
        )));
    }
    Ok(())
}

pub fn still_allowed(
    accounts: &Accounts,
    caller: &Caller,
    account: &str,
    users: &[OsUser],
) -> bool {
    select_account(accounts, caller, Some(account), users).is_ok()
}

pub fn account_from_http_host(host: &str) -> Option<String> {
    let host = host
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    let (user, rest) = host.split_once('@')?;
    if user.is_empty() || rest.is_empty() || user.contains(':') {
        return None;
    }
    Some(user.to_string())
}

pub fn personal_paths(
    runtime_dir: Option<&Path>,
    state_home: Option<&Path>,
    home: Option<&Path>,
    uid: u32,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let runtime = runtime_dir
        .map(|dir| dir.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(format!("/run/user/{uid}")));
    let state = state_home
        .map(|dir| dir.to_path_buf())
        .or_else(|| home.map(|dir| dir.join(".local/state")))
        .unwrap_or_else(|| std::path::PathBuf::from(".local/state"));
    (runtime.join("rex/server.sock"), state.join("rex"))
}

fn allowed_names(accounts: &Accounts, caller: &Caller, users: &[OsUser]) -> Vec<String> {
    let mut names = Vec::new();
    let mut star = false;
    for (name, principals) in &accounts.accounts {
        if !principals
            .iter()
            .any(|principal| principal_matches(principal, caller))
        {
            continue;
        }
        if name == "*" {
            star = true;
            continue;
        }
        if caller.anonymous && name == "root" {
            continue;
        }
        names.push(name.clone());
    }
    if star && !caller.anonymous {
        for user in users {
            if user.uid >= 1000 && !names.iter().any(|name| name == &user.name) {
                names.push(user.name.clone());
            }
        }
    }
    names
}

fn default_account(accounts: &Accounts, caller: &Caller) -> Option<String> {
    let mut best: Option<(u8, String)> = None;
    for (principal, account) in &accounts.defaults {
        if !principal_matches(principal, caller) {
            continue;
        }
        let rank = principal_rank(principal);
        if best.as_ref().is_none_or(|(best_rank, _)| rank < *best_rank) {
            best = Some((rank, account.clone()));
        }
    }
    best.map(|(_, account)| account)
}

fn principal_matches(principal: &str, caller: &Caller) -> bool {
    if principal == "anonymous" {
        return caller.anonymous;
    }
    if principal == "identified" {
        return caller.identified && !caller.anonymous;
    }
    if let Some(uid) = principal.strip_prefix("peer:") {
        return caller
            .uid
            .is_some_and(|caller_uid| uid == caller_uid.to_string());
    }
    if principal == "tailscale:tag:*" {
        return !caller.tags.is_empty();
    }
    if let Some(tag) = principal.strip_prefix("tailscale:tag:") {
        return caller
            .tags
            .iter()
            .any(|have| have == &format!("tag:{tag}") || have == tag);
    }
    if principal == "tailscale:*" {
        return caller.tags.is_empty() && caller.tailscale_login.is_some();
    }
    if let Some(login) = principal.strip_prefix("tailscale:") {
        return caller.tags.is_empty() && caller.tailscale_login.as_deref() == Some(login);
    }
    false
}

fn principal_rank(principal: &str) -> u8 {
    if principal.starts_with("tailscale:tag:") && principal != "tailscale:tag:*" {
        1
    } else if principal == "tailscale:*" || principal == "tailscale:tag:*" {
        2
    } else if principal == "identified" {
        3
    } else if principal == "anonymous" {
        4
    } else {
        0
    }
}

fn strip_jsonc(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    strip_trailing_commas(&out)
}

fn strip_trailing_commas(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }
        if ch == ',' {
            let mut look = chars.clone();
            let next = look.find(|item| !item.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        out.push(ch);
    }
    out
}

fn ordered_object_pairs(json: &str, key: &str) -> Option<Vec<(String, String)>> {
    let object = object_body(json, key)?;
    let mut pairs = Vec::new();
    let value: BTreeMap<String, Value> = serde_json::from_str(&format!("{{{object}}}")).ok()?;
    let _ = value;
    let mut rest = object.trim();
    if rest.starts_with('{') {
        rest = rest[1..].trim();
    }
    if let Some(stripped) = rest.strip_suffix('}') {
        rest = stripped.trim();
    }
    while !rest.is_empty() {
        rest = rest.trim_start_matches(',').trim();
        if rest.is_empty() {
            break;
        }
        let parsed: Value = serde_json::from_str(&format!("{{{rest}}}")).ok()?;
        let map = parsed.as_object()?;
        if map.len() != 1 && !rest.contains(',') {
            // fall through
        }
        let name_end = rest.find('"')?;
        let after = &rest[name_end + 1..];
        let key_end = after.find('"')?;
        let name = after[..key_end].to_string();
        let after_key = after[key_end + 1..]
            .trim_start()
            .trim_start_matches(':')
            .trim_start();
        let value_text = json_value(after_key)?;
        let parsed_value: Value = serde_json::from_str(value_text).ok()?;
        if let Some(account) = parsed_value.as_str() {
            pairs.push((name, account.to_string()));
        }
        rest = after_key[value_text.len()..].trim_start();
    }
    Some(pairs)
}

fn ordered_accounts(json: &str) -> Option<Vec<(String, Vec<String>)>> {
    let object = object_body(json, "accounts")?;
    let mut rest = object.trim();
    if let Some(inner) = rest.strip_prefix('{') {
        rest = inner;
    }
    if let Some(inner) = rest.trim_end().strip_suffix('}') {
        rest = inner;
    }
    let mut accounts = Vec::new();
    rest = rest.trim();
    while !rest.is_empty() {
        rest = rest.trim_start_matches(',').trim();
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with('"') {
            return None;
        }
        let after = &rest[1..];
        let key_end = after.find('"')?;
        let name = after[..key_end].to_string();
        let after_key = after[key_end + 1..]
            .trim_start()
            .trim_start_matches(':')
            .trim_start();
        let value_text = json_value(after_key)?;
        let parsed: Value = serde_json::from_str(value_text).ok()?;
        let principals = parsed
            .get("principals")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        accounts.push((name, principals));
        rest = after_key[value_text.len()..].trim_start();
    }
    Some(accounts)
}

fn object_body<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("\"{key}\"");
    let start = json.find(&pattern)?;
    let after = &json[start + pattern.len()..];
    let colon = after.find(':')?;
    let value = after[colon + 1..].trim_start();
    json_value(value)
}

fn json_value(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    let first = chars.next()?;
    if first == '"' {
        let mut escape = false;
        for (index, ch) in text.char_indices().skip(1) {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == '"' {
                return Some(&text[..=index]);
            }
        }
        return None;
    }
    if first != '{' && first != '[' {
        let end = text.find([',', '}', ']']).unwrap_or(text.len());
        return Some(text[..end].trim_end());
    }
    let open = first;
    let close = if open == '{' { '}' } else { ']' };
    let mut depth = 0;
    let mut in_string = false;
    let mut escape = false;
    for (index, ch) in text.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            ch if ch == open => depth += 1,
            ch if ch == close => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[..=index]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Caller {
        Caller {
            tailscale_login: Some("alice@example.com".into()),
            tags: Vec::new(),
            uid: Some(1000),
            identified: true,
            anonymous: false,
        }
    }

    fn users() -> Vec<OsUser> {
        vec![
            OsUser {
                name: "alice".into(),
                uid: 1000,
                gid: 1000,
                home: "/home/alice".into(),
                shell: "/bin/bash".into(),
                locked: false,
            },
            OsUser {
                name: "root".into(),
                uid: 0,
                gid: 0,
                home: "/root".into(),
                shell: "/bin/bash".into(),
                locked: false,
            },
            OsUser {
                name: "bob".into(),
                uid: 1001,
                gid: 1001,
                home: "/home/bob".into(),
                shell: "/bin/bash".into(),
                locked: false,
            },
            OsUser {
                name: "nobody".into(),
                uid: 65534,
                gid: 65534,
                home: "/nonexistent".into(),
                shell: "/usr/sbin/nologin".into(),
                locked: true,
            },
        ]
    }

    #[test]
    fn jsonc_comments_trailing_commas_and_selection() {
        let accounts = parse_accounts(
            r#"{
              // who may log in
              "version": 1,
              "accounts": {
                "alice": { "principals": ["tailscale:alice@example.com"] },
                "root": { "principals": ["tailscale:alice@example.com"] },
              },
              "defaults": { "tailscale:*": "root", "tailscale:alice@example.com": "alice", },
            }"#,
        )
        .unwrap();
        assert_eq!(accounts.version, 1);
        assert_eq!(accounts.defaults[0].0, "tailscale:*");
        assert_eq!(accounts.defaults[1].1, "alice");
        let chosen = select_account(&accounts, &alice(), None, &users()).unwrap();
        assert_eq!(chosen, "alice");
        assert_eq!(
            select_account(&accounts, &alice(), Some("root"), &users()).unwrap(),
            "root"
        );
        let ordered = parse_accounts(
            r#"{ "accounts": { "from-peer": { "principals": ["peer:1000"] }, "from-login": { "principals": ["tailscale:alice@example.com"] } }, "defaults": { "peer:1000": "from-peer", "tailscale:alice@example.com": "from-login" } }"#,
        )
        .unwrap();
        assert_eq!(ordered.defaults[0].0, "peer:1000");
        assert_eq!(
            select_account(&ordered, &alice(), None, &users()).unwrap(),
            "from-peer"
        );
        let tagged = Caller {
            tailscale_login: Some("ci@example.com".into()),
            tags: vec!["tag:ci".into()],
            uid: None,
            identified: true,
            anonymous: false,
        };
        assert!(!super::principal_matches("tailscale:*", &tagged));
        assert!(super::principal_matches("tailscale:tag:ci", &tagged));
        assert!(super::principal_matches("tailscale:tag:*", &tagged));
    }

    #[test]
    fn star_anonymous_and_policy() {
        let err = parse_accounts(
            r#"{ "version": 1, "accounts": { "*": { "principals": ["anonymous"] } } }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("anonymous"), "{err}");

        let accounts = parse_accounts(
            r#"{ "version": 1, "accounts": { "*": { "principals": ["tailscale:*"] }, "root": { "principals": ["anonymous"] } } }"#,
        )
        .unwrap();
        let anon = Caller {
            tailscale_login: None,
            tags: Vec::new(),
            uid: None,
            identified: false,
            anonymous: true,
        };
        assert!(select_account(&accounts, &anon, Some("root"), &users()).is_err());
        assert_eq!(
            select_account(&accounts, &alice(), Some("bob"), &users()).unwrap(),
            "bob"
        );
        let nobody = users()
            .into_iter()
            .find(|user| user.name == "nobody")
            .unwrap();
        assert!(may_login(&nobody, &alice()).is_err());
        assert!(policy_from_files(&users()[0], true, false).is_err());
        assert!(policy_from_files(&users()[1], true, true).is_ok());
        assert_eq!(
            account_from_http_host("https://root@build.example.ts.net").as_deref(),
            Some("root")
        );
        assert!(account_from_http_host("build.example.ts.net").is_none());
        let (socket, state) = personal_paths(None, None, Some(Path::new("/home/alice")), 1000);
        assert_eq!(socket, Path::new("/run/user/1000/rex/server.sock"));
        assert_eq!(state, Path::new("/home/alice/.local/state/rex"));
        let next = parse_accounts(
            r#"{ "version": 1, "accounts": { "alice": { "principals": ["tailscale:alice@example.com"] } } }"#,
        )
        .unwrap();
        assert!(!still_allowed(&next, &alice(), "root", &users()));
        assert!(still_allowed(&next, &alice(), "alice", &users()));
    }
}
