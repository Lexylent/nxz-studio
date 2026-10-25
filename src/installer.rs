use crate::error::NxzError;
use crate::shell::{register_windows_context_menu_for_exe, unregister_windows_context_menu};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const APP_DISPLAY_NAME: &str = "NXZ Studio — High-Speed Smart Archiver";
pub const APP_VERSION: &str = "2.2.0";
pub const APP_PUBLISHER: &str = "NXZ Open Source Project";
pub const UNINSTALL_REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NXZStudio";

pub fn default_install_dir() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        if !local_app_data.trim().is_empty() {
            return PathBuf::from(local_app_data).join("Programs").join("NXZ Studio");
        }
    }
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        return PathBuf::from(user_profile)
            .join("AppData")
            .join("Local")
            .join("Programs")
            .join("NXZ Studio");
    }
    PathBuf::from(r"C:\Program Files\NXZ Studio")
}

pub fn desktop_shortcut_path() -> Option<PathBuf> {
    std::env::var("USERPROFILE")
        .ok()
        .map(|p| PathBuf::from(p).join("Desktop").join("NXZ Studio.lnk"))
}

pub fn start_menu_shortcut_path() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(|p| {
        PathBuf::from(p)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("NXZ Studio.lnk")
    })
}

pub fn is_setup_executable_name(exe_path: &Path) -> bool {
    let stem = exe_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    stem.contains("setup") || stem.contains("installer")
}

pub fn is_uninstall_executable_name(exe_path: &Path) -> bool {
    let stem = exe_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    stem.contains("uninstall")
}

pub fn install_application(
    create_desktop_shortcut: bool,
    create_start_menu: bool,
    register_shell: bool,
) -> Result<PathBuf, NxzError> {
    let current_exe = std::env::current_exe()?;
    let install_dir = default_install_dir();
    fs::create_dir_all(&install_dir).map_err(|e| NxzError::IoPath {
        path: install_dir.clone(),
        source: e,
    })?;

    let installed_exe = install_dir.join("NXZ-Studio.exe");
    let uninstall_exe = install_dir.join("NXZ-Uninstall.exe");

    if !paths_refer_to_same_file(&current_exe, &installed_exe) {
        fs::copy(&current_exe, &installed_exe).map_err(|e| NxzError::IoPath {
            path: installed_exe.clone(),
            source: e,
        })?;
    }

    if !paths_refer_to_same_file(&current_exe, &uninstall_exe) {
        fs::copy(&current_exe, &uninstall_exe).map_err(|e| NxzError::IoPath {
            path: uninstall_exe.clone(),
            source: e,
        })?;
    }

    if register_shell {
        register_windows_context_menu_for_exe(&installed_exe)
            .map_err(|e| NxzError::Io(io::Error::new(io::ErrorKind::Other, e)))?;
    }

    if create_desktop_shortcut {
        if let Some(lnk_path) = desktop_shortcut_path() {
            if let Some(desktop_dir) = lnk_path.parent() {
                let _ = fs::create_dir_all(desktop_dir);
                let loose_exe = desktop_dir.join("NXZ-Studio.exe");
                if loose_exe.exists() && !paths_refer_to_same_file(&current_exe, &loose_exe) {
                    let _ = fs::remove_file(&loose_exe);
                }
            }
            create_windows_shortcut(
                &lnk_path,
                &installed_exe,
                &install_dir,
                "NXZ Studio — High-Speed Smart Archiver",
            )?;
        }
    }

    if create_start_menu {
        if let Some(start_lnk) = start_menu_shortcut_path() {
            if let Some(parent) = start_lnk.parent() {
                let _ = fs::create_dir_all(parent);
            }
            create_windows_shortcut(
                &start_lnk,
                &installed_exe,
                &install_dir,
                "NXZ Studio — High-Speed Smart Archiver",
            )?;
        }
    }

    register_uninstaller_in_registry(&install_dir, &installed_exe, &uninstall_exe)?;

    Ok(installed_exe)
}

pub fn uninstall_application() -> Result<(), NxzError> {
    let _ = unregister_windows_context_menu();

    let _ = Command::new("reg")
        .args(["delete", UNINSTALL_REG_KEY, "/f"])
        .output();

    if let Some(desktop_lnk) = desktop_shortcut_path() {
        let _ = fs::remove_file(desktop_lnk);
    }
    if let Some(start_lnk) = start_menu_shortcut_path() {
        let _ = fs::remove_file(start_lnk);
    }

    let install_dir = default_install_dir();
    let installed_exe = install_dir.join("NXZ-Studio.exe");
    let current_exe = std::env::current_exe().unwrap_or_default();

    if installed_exe.exists() && !paths_refer_to_same_file(&current_exe, &installed_exe) {
        let _ = fs::remove_file(&installed_exe);
    }

    if install_dir.exists() {
        let dir_str = install_dir.to_string_lossy().to_string();
        let cleanup_cmd = format!("timeout /t 2 /nobreak >nul & rmdir /s /q \"{}\"", dir_str);
        let _ = Command::new("cmd.exe")
            .args(["/C", &cleanup_cmd])
            .spawn();
    }

    Ok(())
}

fn paths_refer_to_same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

fn create_windows_shortcut(
    lnk_path: &Path,
    target_exe: &Path,
    working_dir: &Path,
    description: &str,
) -> Result<(), NxzError> {
    let lnk = lnk_path.to_string_lossy().replace('\'', "''");
    let target = target_exe.to_string_lossy().replace('\'', "''");
    let work = working_dir.to_string_lossy().replace('\'', "''");
    let desc = description.replace('\'', "''");

    let ps_script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{lnk}'); \
         $s.TargetPath = '{target}'; \
         $s.WorkingDirectory = '{work}'; \
         $s.IconLocation = '{target},0'; \
         $s.Description = '{desc}'; \
         $s.Save()"
    );

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_script,
        ])
        .output()?;

    if !output.status.success() {
        return Err(NxzError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to create shortcut '{}': {}",
                lnk_path.display(),
                String::from_utf8_lossy(&output.stderr)
            ),
        )));
    }
    Ok(())
}

fn register_uninstaller_in_registry(
    install_dir: &Path,
    installed_exe: &Path,
    uninstall_exe: &Path,
) -> Result<(), NxzError> {
    let display_icon = format!("{},0", installed_exe.display());
    let install_loc = install_dir.to_string_lossy().to_string();
    let uninstall_str = format!("\"{}\" --uninstall", uninstall_exe.display());

    let str_values = [
        ("DisplayName", APP_DISPLAY_NAME),
        ("DisplayVersion", APP_VERSION),
        ("Publisher", APP_PUBLISHER),
        ("DisplayIcon", &display_icon),
        ("InstallLocation", &install_loc),
        ("UninstallString", &uninstall_str),
    ];

    for (name, val) in str_values {
        let out = Command::new("reg")
            .args(["add", UNINSTALL_REG_KEY, "/v", name, "/t", "REG_SZ", "/d", val, "/f"])
            .output()?;
        if !out.status.success() {
            return Err(NxzError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to write Uninstall registry value {name}: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
            )));
        }
    }

    let dword_values = [
        ("NoModify", "1"),
        ("NoRepair", "1"),
        ("EstimatedSize", "5120"),
    ];

    for (name, val) in dword_values {
        let _ = Command::new("reg")
            .args([
                "add",
                UNINSTALL_REG_KEY,
                "/v",
                name,
                "/t",
                "REG_DWORD",
                "/d",
                val,
                "/f",
            ])
            .output();
    }

    Ok(())
}
