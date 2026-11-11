//! The compose files under `deploy/`, read as text. No Docker and no database.
//!
//! `deploy/compose.yml` gives the serving container its environment. The other files in that
//! directory are laid over it (`-f compose.yml -f compose.passkey.yml ...`). One of them once
//! replaced the whole environment with `!override` and so lost `TINYSERVER_E2EE_KEY_FILE`: the
//! server then looked for its end-to-end key on a tmpfs, did not find it, and would not start.
//! These tests merge every combination of those files the way compose does and fail when a
//! variable from `compose.yml` goes missing or changes without being on the short list below.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const BASE: &str = "compose.yml";
const SERVICE: &str = "tinyserver";
const KEY_FILE: &str = "/var/lib/tinyserver-keys/e2ee-server-key";

/// What an overlay may change. Everything else must reach the container as `compose.yml` wrote
/// it. The provider's settings are emptied by `compose.passkey.yml`; the scanner's are changed
/// by `scan-off.yml`.
fn may_change(key: &str) -> bool {
    key.starts_with("TINYSERVER_OIDC_")
        || key == "TINYSERVER_SCAN_ENGINE"
        || key == "TINYSERVER_CLAMD_SOCKET"
}

/// One service of one compose file: its keys with whatever follows the colon, and its
/// environment in file order.
#[derive(Default)]
struct Service {
    keys: BTreeMap<String, String>,
    environment: Vec<(String, String)>,
}

fn deploy_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy")
}

fn read(name: &str) -> String {
    let path = deploy_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

/// The compose files here keep to two spaces a level and write `environment` as a map, which is
/// all this reads. A file that does neither fails loudly instead of passing unread.
fn service(file: &str, name: &str) -> Option<Service> {
    let text = read(file);
    let mut in_services = false;
    let mut in_service = false;
    let mut in_environment = false;
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match indent(line) {
            0 => {
                in_services = trimmed == "services:";
                in_service = false;
                in_environment = false;
            }
            2 if in_services => {
                in_service = trimmed == format!("{name}:");
                in_environment = false;
                if in_service {
                    found.get_or_insert_with(Service::default);
                }
            }
            4 if in_service => {
                let (key, rest) = trimmed
                    .split_once(':')
                    .unwrap_or_else(|| panic!("{file}: `{trimmed}` is not a key"));
                in_environment = key == "environment";
                let service = found.as_mut().expect("the service was found above");
                service
                    .keys
                    .insert(key.to_string(), rest.trim().to_string());
            }
            6 if in_service && in_environment => {
                assert!(
                    !trimmed.starts_with('-'),
                    "{file}: write {name}'s environment as a map, not a list"
                );
                let (key, value) = trimmed
                    .split_once(':')
                    .unwrap_or_else(|| panic!("{file}: `{trimmed}` is not a variable"));
                let service = found.as_mut().expect("the service was found above");
                service.environment.push((key.to_string(), unquote(value)));
            }
            _ => {}
        }
    }
    found
}

/// Every compose file in `deploy/` that is laid over `compose.yml`.
fn overlays() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(deploy_dir())
        .expect("deploy/ is readable")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".yml") && name != BASE)
        .collect();
    names.sort();
    names
}

/// Every non-empty choice of the overlays, in every order.
fn combinations(names: &[String]) -> Vec<Vec<String>> {
    fn grow(names: &[String], chosen: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        for name in names {
            if chosen.contains(name) {
                continue;
            }
            chosen.push(name.clone());
            out.push(chosen.clone());
            grow(names, chosen, out);
            chosen.pop();
        }
    }
    let mut out = Vec::new();
    grow(names, &mut Vec::new(), &mut out);
    out
}

/// The environment compose gives the service: maps merge key by key, a later file wins,
/// `!override` and `!reset` on the map replace or drop it, and `!reset` on a value drops it.
fn merged(files: &[String]) -> BTreeMap<String, String> {
    let mut environment: BTreeMap<String, String> = service(BASE, SERVICE)
        .expect("compose.yml has the service")
        .environment
        .into_iter()
        .collect();
    for file in files {
        let Some(overlay) = service(file, SERVICE) else {
            continue;
        };
        if overlay
            .keys
            .get("environment")
            .is_some_and(|tag| tag.starts_with('!'))
        {
            environment.clear();
        }
        for (key, value) in overlay.environment {
            if value.starts_with("!reset") {
                environment.remove(&key);
            } else {
                environment.insert(key, value);
            }
        }
    }
    environment
}

#[test]
fn compose_yml_keeps_the_e2ee_key_on_a_volume() {
    let base = service(BASE, SERVICE).expect("compose.yml has the service");
    let environment: BTreeMap<_, _> = base.environment.into_iter().collect();
    assert_eq!(
        environment
            .get("TINYSERVER_E2EE_KEY_FILE")
            .map(String::as_str),
        Some(KEY_FILE)
    );
    // The data directory is a tmpfs there. The key must not be under it.
    let data_dir = &environment["TINYSERVER_DATA_DIR"];
    assert!(read(BASE).contains(&format!("- {data_dir}:uid=10001")));
    assert!(!KEY_FILE.starts_with(&format!("{data_dir}/")));
    assert!(read(BASE)
        .lines()
        .any(|line| line.trim() == "- tinyserver_keys:/var/lib/tinyserver-keys"));
    for required in [
        "DATABASE_URL",
        "BIND",
        "TINYSERVER_PUBLIC_URL",
        "TINYSERVER_MEDIA_HMAC_SECRET",
        "TINYSERVER_UPLOAD_DIR",
        "TINYSERVER_SCAN_ENGINE",
    ] {
        assert!(environment.contains_key(required), "{required}");
    }
}

#[test]
fn every_overlay_combination_keeps_what_compose_yml_gives_the_server() {
    let base = merged(&[]);
    let names = overlays();
    for known in [
        "compose.image.yml",
        "compose.passkey.yml",
        "compose.proxy.yml",
        "scan-off.yml",
    ] {
        assert!(names.iter().any(|name| name == known), "{known} is gone");
    }
    let combinations = combinations(&names);
    assert!(combinations.len() >= 64);
    for files in combinations {
        let environment = merged(&files);
        for (key, value) in &base {
            let Some(now) = environment.get(key) else {
                panic!("{files:?} drops {key}");
            };
            assert!(
                now == value || may_change(key),
                "{files:?} changes {key} to `{now}`"
            );
        }
        assert_eq!(
            environment["TINYSERVER_E2EE_KEY_FILE"], KEY_FILE,
            "{files:?}"
        );
        if files.iter().any(|file| file == "compose.passkey.yml") {
            // tinyserver reads an empty setting as unset, so this is "no provider".
            for (key, value) in &environment {
                assert!(
                    !key.starts_with("TINYSERVER_OIDC_") || value.is_empty(),
                    "{files:?} leaves {key} set with Pocket ID gone"
                );
            }
        }
        if files.iter().any(|file| file == "scan-off.yml") {
            assert_eq!(environment["TINYSERVER_SCAN_ENGINE"], "none", "{files:?}");
            assert_eq!(environment["TINYSERVER_CLAMD_SOCKET"], "", "{files:?}");
        }
    }
}

/// A map an overlay replaces whole loses whatever `compose.yml` adds to it later, and two
/// overlays that each replace `depends_on` cannot be used together.
#[test]
fn no_overlay_replaces_a_whole_map_of_the_server() {
    for file in overlays() {
        let Some(overlay) = service(&file, SERVICE) else {
            continue;
        };
        for map in ["environment", "depends_on", "volumes", "tmpfs"] {
            let tag = overlay.keys.get(map).map(String::as_str).unwrap_or("");
            assert!(
                !tag.starts_with('!'),
                "{file}: `{map}: {tag}` replaces everything compose.yml gives {SERVICE}; \
                 change single entries instead"
            );
        }
        for (key, value) in &overlay.environment {
            assert!(
                !value.starts_with('!'),
                "{file}: empty {key} with \"\" instead of `{value}`"
            );
        }
    }
}

/// The commands in deploy/README.md name only files the tests above cover.
#[test]
fn the_readme_names_only_compose_files_that_are_checked() {
    let names = overlays();
    let text = std::fs::read_to_string(deploy_dir().join("README.md")).expect("deploy/README.md");
    let mut seen = 0;
    for word in text.split(|c: char| c.is_whitespace() || c == '`') {
        if !word.ends_with(".yml") || word.contains('/') {
            continue;
        }
        seen += 1;
        assert!(
            word == BASE || names.iter().any(|name| name == word),
            "deploy/README.md names {word}, which is not in deploy/"
        );
    }
    assert!(seen >= 4);
}
