#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::{Parser, Subcommand, ValueEnum};
use nxz::gui::{
    launch_desktop_gui, launch_desktop_gui_with_action, launch_setup_wizard_gui,
    launch_uninstall_notice_gui, StartupAction,
};
use nxz::installer::{
    is_setup_executable_name, is_uninstall_executable_name, uninstall_application,
};
use nxz::pipeline::{
    extract_single_file_with_password, pack_with_options, read_archive_index_with_password,
    unpack_all_with_password, PackOptions,
};
use nxz::router::{analyze_file_route, CompressionProfile};
use nxz::shell::{register_windows_context_menu, unregister_windows_context_menu};
use std::path::PathBuf;
use std::time::Instant;

#[cfg(windows)]
const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF;

#[cfg(windows)]
extern "system" {
    fn AttachConsole(dwProcessId: u32) -> i32;
}

#[derive(Parser)]
#[command(
    name = "nxz",
    version = "2.2.0",
    about = "NXZ Studio & CLI — NextGen High-Speed Archiver (FOT-2 + Office-Unfold + AEAD + Reed-Solomon + GUI)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliProfile {
    Turbo,
    Balanced,
    Ultra,
}

impl From<CliProfile> for CompressionProfile {
    fn from(p: CliProfile) -> Self {
        match p {
            CliProfile::Turbo => CompressionProfile::Turbo,
            CliProfile::Balanced => CompressionProfile::Balanced,
            CliProfile::Ultra => CompressionProfile::Ultra,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    Gui,
    Pack {
        input: PathBuf,
        output: PathBuf,
        #[arg(short, long, value_enum, default_value_t = CliProfile::Balanced)]
        profile: CliProfile,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        ecc: bool,
    },
    Unpack {
        archive: PathBuf,
        output_dir: PathBuf,
        #[arg(short, long)]
        file: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    QuickPack {
        input: PathBuf,
    },
    QuickUnpack {
        archive: PathBuf,
    },
    GuiPack {
        input: PathBuf,
    },
    GuiUnpack {
        archive: PathBuf,
    },
    List {
        archive: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    Inspect {
        file: PathBuf,
    },
    ExtractFile {
        archive: PathBuf,
        file: String,
        output_dir: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    Setup,
    Uninstall,
    RegisterShell,
    UnregisterShell,
}

fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }

    let raw_args: Vec<String> = std::env::args().collect();
    let current_exe = std::env::current_exe().unwrap_or_default();

    if raw_args
        .iter()
        .skip(1)
        .any(|a| a.eq_ignore_ascii_case("--uninstall") || a.eq_ignore_ascii_case("uninstall"))
        || (raw_args.len() == 1 && is_uninstall_executable_name(&current_exe))
    {
        let res = uninstall_application().map_err(|e| e.to_string());
        match &res {
            Ok(()) => println!("NXZ Studio wurde erfolgreich deinstalliert."),
            Err(e) => eprintln!("Deinstallation fehlgeschlagen: {e}"),
        }
        let _ = launch_uninstall_notice_gui(res);
        return Ok(());
    }

    if raw_args
        .iter()
        .skip(1)
        .any(|a| a.eq_ignore_ascii_case("--setup") || a.eq_ignore_ascii_case("setup"))
        || (raw_args.len() == 1 && is_setup_executable_name(&current_exe))
    {
        let _ = launch_setup_wizard_gui();
        return Ok(());
    }

    if raw_args.len() == 2 {
        let arg = &raw_args[1];
        let lower = arg.to_ascii_lowercase();
        let is_known_cmd = arg.starts_with('-')
            || matches!(
                lower.as_str(),
                "gui"
                    | "pack"
                    | "unpack"
                    | "quick-pack"
                    | "quick-unpack"
                    | "gui-pack"
                    | "gui-unpack"
                    | "extract-file"
                    | "list"
                    | "inspect"
                    | "setup"
                    | "uninstall"
                    | "register-shell"
                    | "unregister-shell"
                    | "help"
            );
        if !is_known_cmd {
            let _ = launch_desktop_gui_with_action(Some(StartupAction::OpenOnly(PathBuf::from(arg))));
            return Ok(());
        }
    }

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Gui) {
        Commands::Gui => {
            let _ = launch_desktop_gui();
        }
        Commands::Pack {
            input,
            output,
            profile,
            password,
            ecc,
        } => {
            let start = Instant::now();
            let opts = PackOptions {
                profile: profile.into(),
                password,
                enable_ecc: ecc,
                progress: None,
            };
            let footer = pack_with_options(&input, &output, &opts)?;
            let elapsed = start.elapsed().as_secs_f64().max(0.0001);
            let mbs = (footer.total_uncompressed_bytes as f64 / (1024.0 * 1024.0)) / elapsed;
            let ratio = if footer.total_uncompressed_bytes > 0 {
                (footer.total_stored_bytes as f64 / footer.total_uncompressed_bytes as f64) * 100.0
            } else {
                100.0
            };
            println!("=== NXZ PACK COMPLETE ===");
            println!("Files packed    : {}", footer.total_files);
            println!("Seekable Blocks : {}", footer.blocks.len());
            println!("Original Size   : {} B", footer.total_uncompressed_bytes);
            println!("Stored Size     : {} B ({:.2}%)", footer.total_stored_bytes, ratio);
            println!("AEAD Encrypted  : {}", footer.encrypted);
            println!("Reed-Solomon ECC: {}", footer.ecc_enabled);
            println!("Throughput      : {:.3} s ({:.1} MB/s)", elapsed, mbs);
        }
        Commands::Unpack {
            archive,
            output_dir,
            file,
            password,
        } => {
            let start = Instant::now();
            let pw = password.as_deref();
            if let Some(target_file) = file {
                let path = extract_single_file_with_password(&archive, &target_file, &output_dir, pw)?;
                println!(
                    "=== INSTANT SEEK EXTRACTION COMPLETE ({:.2} ms) ===",
                    start.elapsed().as_secs_f64() * 1000.0
                );
                println!("Extracted: {}", path.display());
            } else {
                let (footer, healed) = unpack_all_with_password(&archive, &output_dir, pw)?;
                let elapsed = start.elapsed().as_secs_f64().max(0.0001);
                let mbs = (footer.total_uncompressed_bytes as f64 / (1024.0 * 1024.0)) / elapsed;
                println!("=== NXZ UNPACK COMPLETE ===");
                println!("Files verified & extracted : {}", footer.total_files);
                if healed > 0 {
                    println!("Self-Healed Corrupted Shards: {}", healed);
                }
                println!("Throughput                 : {:.3} s ({:.1} MB/s)", elapsed, mbs);
            }
        }
        Commands::QuickPack { input } => {
            let output = PathBuf::from(format!("{}.nxz", input.display()));
            let opts = PackOptions {
                profile: CompressionProfile::Balanced,
                password: None,
                enable_ecc: false,
                progress: None,
            };
            pack_with_options(&input, &output, &opts)?;
        }
        Commands::QuickUnpack { archive } => {
            let stem = archive.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
            let out_dir = archive.parent().unwrap_or(&archive).join(stem);
            unpack_all_with_password(&archive, &out_dir, None)?;
        }
        Commands::GuiPack { input } => {
            let _ = launch_desktop_gui_with_action(Some(StartupAction::AutoPack(input)));
        }
        Commands::GuiUnpack { archive } => {
            let _ = launch_desktop_gui_with_action(Some(StartupAction::AutoUnpack(archive)));
        }
        Commands::List { archive, password } => {
            let (_hdr, footer, _) = read_archive_index_with_password(&archive, password.as_deref())?;
            println!(
                "NXZ Archive | Files: {} | Blocks: {} | Raw: {} B | Stored: {} B | Encrypted: {} | ECC: {}",
                footer.total_files,
                footer.blocks.len(),
                footer.total_uncompressed_bytes,
                footer.total_stored_bytes,
                footer.encrypted,
                footer.ecc_enabled
            );
            for f in &footer.files {
                println!(
                    "{:<45} | {:>12} B | Block #{} | {:.2} bpb",
                    f.relative_path, f.original_size, f.block_id, f.shannon_entropy_bpb
                );
            }
        }
        Commands::Inspect { file } => {
            let analysis = analyze_file_route(&file, CompressionProfile::Balanced)?;
            println!(
                "File: {} | Entropy: {:.4} bpb | Class: {:?} | Route: {:?}",
                file.display(),
                analysis.shannon_entropy_bpb,
                analysis.detected_class,
                analysis.recommended_route
            );
        }
        Commands::ExtractFile {
            archive,
            file,
            output_dir,
            password,
        } => {
            let start = Instant::now();
            let path = extract_single_file_with_password(&archive, &file, &output_dir, password.as_deref())?;
            println!(
                "=== INSTANT SEEK EXTRACTION COMPLETE ({:.2} ms) ===",
                start.elapsed().as_secs_f64() * 1000.0
            );
            println!("Extracted: {}", path.display());
        }
        Commands::Setup => {
            let _ = launch_setup_wizard_gui();
        }
        Commands::Uninstall => {
            let res = uninstall_application().map_err(|e| e.to_string());
            let _ = launch_uninstall_notice_gui(res);
        }
        Commands::RegisterShell => match register_windows_context_menu() {
            Ok(msg) => println!("{msg}"),
            Err(e) => eprintln!("{e}"),
        },
        Commands::UnregisterShell => match unregister_windows_context_menu() {
            Ok(msg) => println!("{msg}"),
            Err(e) => eprintln!("{e}"),
        },
    }

    Ok(())
}
