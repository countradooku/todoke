//! Service definitions that start the daemon with the user's session.
//!
//! These are printed for the user to install (`todoke daemon service
//! <kind>`); nothing here changes system configuration on its own. Each
//! runs the daemon as the user, never as root or `SYSTEM`: received files
//! belong to the user, and the state directory is the user's. On Windows
//! that means a scheduled task at logon rather than a Windows service
//! (which runs under another account).

use std::path::Path;

/// The service managers supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A systemd user unit (`~/.config/systemd/user/todoke.service`).
    Systemd,
    /// A launchd agent (`~/Library/LaunchAgents/org.todoke.daemon.plist`).
    Launchd,
    /// A Windows Task Scheduler task run at logon (`schtasks /create /xml`).
    WindowsTask,
}

impl Kind {
    /// All kinds, in a fixed order.
    pub const ALL: [Self; 3] = [Self::Systemd, Self::Launchd, Self::WindowsTask];

    /// The kind's name on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
            Self::WindowsTask => "windows",
        }
    }

    /// Where the definition is installed, for the user's reference.
    #[must_use]
    pub const fn location(self) -> &'static str {
        match self {
            Self::Systemd => "~/.config/systemd/user/todoke.service",
            Self::Launchd => "~/Library/LaunchAgents/org.todoke.daemon.plist",
            Self::WindowsTask => "schtasks /create /tn todoke /xml todoke-task.xml",
        }
    }
}

/// The definition of `kind` that runs `exe daemon run`; `None` for a path
/// no format can hold faithfully (not Unicode, or with control
/// characters, which could start a new unit line or are invalid XML).
#[must_use]
pub fn definition(kind: Kind, exe: &Path) -> Option<String> {
    let exe = exe
        .to_str()
        .filter(|exe| !exe.chars().any(char::is_control))?;
    Some(match kind {
        Kind::Systemd => format!(
            "[Unit]\n\
             Description=todoke file transfer daemon\n\
             \n\
             [Service]\n\
             ExecStart={} daemon run\n\
             Restart=on-failure\n\
             NoNewPrivileges=yes\n\
             PrivateTmp=yes\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            systemd_quote(exe)
        ),
        Kind::Launchd => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\t<string>org.todoke.daemon</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\t\t<string>{}</string>\n\t\t<string>daemon</string>\n\t\t<string>run</string>\n\t</array>\n\
             \t<key>RunAtLoad</key>\n\t<true/>\n\
             \t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n\
             \t<key>ProcessType</key>\n\t<string>Background</string>\n\
             </dict>\n\
             </plist>\n",
            xml_escape(exe)
        ),
        Kind::WindowsTask => format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
             \x20 <Triggers>\n    <LogonTrigger>\n      <Enabled>true</Enabled>\n    </LogonTrigger>\n  </Triggers>\n\
             \x20 <Principals>\n    <Principal id=\"Author\">\n      <LogonType>InteractiveToken</LogonType>\n      <RunLevel>LeastPrivilege</RunLevel>\n    </Principal>\n  </Principals>\n\
             \x20 <Settings>\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n    <RestartOnFailure>\n      <Interval>PT1M</Interval>\n      <Count>3</Count>\n    </RestartOnFailure>\n  </Settings>\n\
             \x20 <Actions Context=\"Author\">\n    <Exec>\n      <Command>{}</Command>\n      <Arguments>daemon run</Arguments>\n    </Exec>\n  </Actions>\n\
             </Task>\n",
            xml_escape(exe)
        ),
    })
}

/// Escapes text for an XML element.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// Quotes a path for a systemd `ExecStart=` line.
fn systemd_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            // `%` starts a specifier and `$` a variable in ExecStart.
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitions_run_the_daemon_as_the_user() {
        let exe = Path::new("/opt/todoke/bin/todoke");
        let systemd = definition(Kind::Systemd, exe).unwrap_or_default();
        assert!(systemd.contains("ExecStart=\"/opt/todoke/bin/todoke\" daemon run"));
        assert!(!systemd.contains("User=root"));
        let launchd = definition(Kind::Launchd, exe).unwrap_or_default();
        assert!(launchd.contains("<string>/opt/todoke/bin/todoke</string>"));
        assert!(launchd.contains("org.todoke.daemon"));
        let windows = definition(
            Kind::WindowsTask,
            Path::new(r"C:\Program Files\todoke\todoke.exe"),
        )
        .unwrap_or_default();
        assert!(windows.contains(r"<Command>C:\Program Files\todoke\todoke.exe</Command>"));
        assert!(windows.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    }

    /// A path cannot break out of its field.
    #[test]
    fn hostile_paths_are_escaped() {
        let exe = Path::new("/tmp/a\"b<c>&$HOME%n\\x");
        let systemd = definition(Kind::Systemd, exe).unwrap_or_default();
        assert!(
            systemd.contains(r#"ExecStart="/tmp/a\"b<c>&$$HOME%%n\\x" daemon run"#),
            "{systemd}"
        );
        let windows = definition(Kind::WindowsTask, exe).unwrap_or_default();
        assert!(
            windows.contains("<Command>/tmp/a&quot;b&lt;c&gt;&amp;$HOME%n\\x</Command>"),
            "{windows}"
        );
        let launchd = definition(Kind::Launchd, exe).unwrap_or_default();
        assert!(
            launchd.contains("/tmp/a&quot;b&lt;c&gt;&amp;$HOME%n\\x"),
            "{launchd}"
        );
        assert!(!launchd.contains("<c>"));
        // A line break cannot start a unit line of its own.
        for kind in [Kind::Systemd, Kind::Launchd, Kind::WindowsTask] {
            assert_eq!(definition(kind, Path::new("/a\nExecStartPre=/bin/x")), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn paths_that_are_not_unicode_are_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        let exe = Path::new(std::ffi::OsStr::from_bytes(b"/opt/\xff/todoke"));
        assert_eq!(definition(Kind::Systemd, exe), None);
    }
}
