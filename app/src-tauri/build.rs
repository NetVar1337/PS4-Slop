fn main() {
    csp::check();

    // Release ships requireAdministrator: host packet capture (SIO_RCVALL raw
    // sockets) needs it, and the engine sidecar (asInvoker) inherits the
    // elevated token so only one UAC prompt appears for the whole app.
    //
    // Debug builds are asInvoker instead. An elevated exe cannot be launched by
    // an ordinary terminal, so requiring it here would mean `tauri dev` only
    // works from an elevated shell, and front-end work does not need capture:
    // an unelevated engine just reports capture as unavailable.
    #[cfg(windows)]
    {
        let dev = std::env::var("PROFILE").is_ok_and(|p| p == "debug");
        let manifest = if dev {
            include_str!("app.dev.manifest")
        } else {
            include_str!("app.manifest")
        };
        let attrs = tauri_build::WindowsAttributes::new().app_manifest(manifest);
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(attrs))
            .expect("failed to run tauri-build");
    }
    #[cfg(not(windows))]
    tauri_build::build();
}

/// One CSP, two carriers: tauri.conf.json `app.security.csp` is the source of
/// truth (Tauri injects it into the bundled pages), and app/index.html repeats
/// it as a <meta> tag so plain browser dev on the Vite server gets the same
/// policy. The build fails when they drift apart.
mod csp {
    use std::path::Path;

    pub fn check() {
        let conf_path = Path::new("tauri.conf.json");
        let html_path = Path::new("../index.html");
        println!("cargo:rerun-if-changed={}", conf_path.display());
        println!("cargo:rerun-if-changed={}", html_path.display());

        let conf = std::fs::read_to_string(conf_path).expect("read tauri.conf.json");
        let html = std::fs::read_to_string(html_path).expect("read ../index.html");
        let conf: serde_json::Value = serde_json::from_str(&conf).expect("parse tauri.conf.json");
        let from_conf = conf
            .pointer("/app/security/csp")
            .and_then(|v| v.as_str())
            .expect("tauri.conf.json app.security.csp must be a string");
        let from_html = meta_csp(&html)
            .expect("index.html must carry a Content-Security-Policy <meta> tag");

        if normalize(from_conf) != normalize(from_html) {
            panic!(
                "CSP drift: app/index.html and app/src-tauri/tauri.conf.json disagree\n  \
                 tauri.conf.json: {from_conf}\n  index.html:      {from_html}\n\
                 tauri.conf.json is the source of truth; copy it into index.html's <meta>"
            );
        }
    }

    /// content attribute of the http-equiv=Content-Security-Policy meta tag
    fn meta_csp(html: &str) -> Option<&str> {
        let lower = html.to_ascii_lowercase();
        let marker = lower.find("http-equiv=\"content-security-policy\"")?;
        let tag_start = lower[..marker].rfind('<')?;
        let tag_end = marker + lower[marker..].find('>')?;
        let tag = &html[tag_start..tag_end];
        let attr = tag.to_ascii_lowercase().find("content=\"")? + "content=\"".len();
        let len = tag[attr..].find('"')?;
        Some(&tag[attr..attr + len])
    }

    /// directive order and whitespace don't change meaning
    fn normalize(csp: &str) -> Vec<String> {
        let mut directives: Vec<String> = csp
            .split(';')
            .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|d| !d.is_empty())
            .collect();
        directives.sort();
        directives
    }
}
