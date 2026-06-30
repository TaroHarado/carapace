use std::path::PathBuf;

fn state_root() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home).join(".saferouter")
    } else {
        PathBuf::from(".saferouter")
    }
}

pub fn state_path(name: &str) -> PathBuf {
    state_root().join(name)
}

pub fn state_dir(name: &str) -> PathBuf {
    state_root().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_path_uses_saferouter_root() {
        let p = state_path("registry.json");
        assert!(p.to_string_lossy().contains(".saferouter"));
        assert!(p.to_string_lossy().contains("registry.json"));
    }

    #[test]
    fn state_dir_uses_saferouter_root() {
        let p = state_dir("quarantine");
        assert!(p.to_string_lossy().contains(".saferouter"));
        assert!(p.to_string_lossy().contains("quarantine"));
    }
}
