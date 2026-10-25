use std::path::{Path, PathBuf};
use std::process::Command;

pub fn register_windows_context_menu() -> Result<String, String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to locate executable path: {e}"))?;
    register_windows_context_menu_for_exe(&exe_path)
}

pub fn register_windows_context_menu_for_exe(exe_path: &Path) -> Result<String, String> {
    let exe_str = exe_path.to_string_lossy();
    let icon_val = format!("\"{}\",0", exe_str);
    let cmd_gui_pack = format!("\"{}\" gui-pack \"%1\"", exe_str);
    let cmd_gui_unpack = format!("\"{}\" gui-unpack \"%1\"", exe_str);
    let cmd_open = format!("\"{}\" \"%1\"", exe_str);

    let commands: [(&str, &str, &str); 25] = [
        (
            r"HKCU\Software\Classes\*\shell\NXZPack",
            "",
            "Mit NXZ packen (Balanced)",
        ),
        (
            r"HKCU\Software\Classes\*\shell\NXZPack",
            "Icon",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\*\shell\NXZPack\command",
            "",
            &cmd_gui_pack,
        ),
        (
            r"HKCU\Software\Classes\Directory\shell\NXZPack",
            "",
            "Ordner mit NXZ packen",
        ),
        (
            r"HKCU\Software\Classes\Directory\shell\NXZPack",
            "Icon",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\Directory\shell\NXZPack\command",
            "",
            &cmd_gui_pack,
        ),
        (
            r"HKCU\Software\Classes\SystemFileAssociations\.nxz\shell\NXZUnpack",
            "",
            "NXZ-Archiv hier entpacken",
        ),
        (
            r"HKCU\Software\Classes\SystemFileAssociations\.nxz\shell\NXZUnpack",
            "Icon",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\SystemFileAssociations\.nxz\shell\NXZUnpack\command",
            "",
            &cmd_gui_unpack,
        ),
        (
            r"HKCU\Software\Classes\.nxz",
            "",
            "NXZArchive",
        ),
        (
            r"HKCU\Software\Classes\NXZArchive",
            "",
            "NXZ High-Speed Archive",
        ),
        (
            r"HKCU\Software\Classes\NXZArchive\DefaultIcon",
            "",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\NXZArchive\shell\open\command",
            "",
            &cmd_open,
        ),
        (
            r"HKCU\Software\Classes\NXZArchive\shell\NXZUnpack",
            "",
            "NXZ-Archiv hier entpacken",
        ),
        (
            r"HKCU\Software\Classes\NXZArchive\shell\NXZUnpack\command",
            "",
            &cmd_gui_unpack,
        ),
        (
            r"HKCU\Software\Classes\nxz_auto_file\DefaultIcon",
            "",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\nxz_auto_file\shell\open\command",
            "",
            &cmd_open,
        ),
        (
            r"HKCU\Software\Classes\nxz_auto_file\shell\NXZUnpack",
            "",
            "NXZ-Archiv hier entpacken",
        ),
        (
            r"HKCU\Software\Classes\nxz_auto_file\shell\NXZUnpack",
            "Icon",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\nxz_auto_file\shell\NXZUnpack\command",
            "",
            &cmd_gui_unpack,
        ),
        (
            r"HKCU\Software\Classes\Applications\NXZ-Studio.exe\DefaultIcon",
            "",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\Applications\NXZ-Studio.exe\shell\open\command",
            "",
            &cmd_open,
        ),
        (
            r"HKCU\Software\Classes\Applications\NXZ-Studio.exe\shell\NXZUnpack",
            "",
            "NXZ-Archiv hier entpacken",
        ),
        (
            r"HKCU\Software\Classes\Applications\NXZ-Studio.exe\shell\NXZUnpack",
            "Icon",
            &icon_val,
        ),
        (
            r"HKCU\Software\Classes\Applications\NXZ-Studio.exe\shell\NXZUnpack\command",
            "",
            &cmd_gui_unpack,
        ),
    ];

    for (key, value_name, data) in commands {
        let mut cmd = Command::new("reg");
        cmd.arg("add").arg(key);
        if value_name.is_empty() {
            cmd.arg("/ve");
        } else {
            cmd.arg("/v").arg(value_name);
        }
        cmd.arg("/d").arg(data).arg("/f");

        let output = cmd.output().map_err(|e| format!("reg.exe execution failed: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "Registry update failed for {key}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    Ok("Windows-Rechtsklick-Menue und .nxz-Doppelklick erfolgreich aktiviert!".to_string())
}

pub fn install_standalone_on_desktop() -> Result<String, String> {
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Konnte aktuelle .exe nicht ermitteln: {e}"))?;
    let user_profile = std::env::var("USERPROFILE")
        .map_err(|_| "USERPROFILE-Umgebungsvariable nicht gefunden.".to_string())?;
    let desktop_dir = PathBuf::from(user_profile).join("Desktop");
    std::fs::create_dir_all(&desktop_dir)
        .map_err(|e| format!("Desktop-Ordner nicht erreichbar: {e}"))?;

    let target_exe = desktop_dir.join("NXZ-Studio.exe");
    if current_exe != target_exe {
        std::fs::copy(&current_exe, &target_exe)
            .map_err(|e| format!("Kopieren auf den Desktop fehlgeschlagen: {e}"))?;
    }

    register_windows_context_menu_for_exe(&target_exe)?;

    Ok(format!(
        "🚀 Standalone-App installiert unter '{}' und mit Rechtsklick-Menue sowie .nxz-Doppelklick verknuepft!",
        target_exe.display()
    ))
}

pub fn unregister_windows_context_menu() -> Result<String, String> {
    let keys = [
        r"HKCU\Software\Classes\*\shell\NXZPack",
        r"HKCU\Software\Classes\Directory\shell\NXZPack",
        r"HKCU\Software\Classes\SystemFileAssociations\.nxz\shell\NXZUnpack",
        r"HKCU\Software\Classes\NXZArchive",
        r"HKCU\Software\Classes\.nxz",
    ];

    for key in keys {
        let _ = Command::new("reg").arg("delete").arg(key).arg("/f").output();
    }

    Ok("Windows-Rechtsklick-Menue und .nxz-Verknuepfung wieder entfernt.".to_string())
}
