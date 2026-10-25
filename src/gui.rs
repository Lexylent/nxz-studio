use crate::container::SeekableIndexFooter;
use crate::installer::{default_install_dir, install_application, uninstall_application};
use crate::office::extract_standard_zip;
use crate::pipeline::{
    extract_single_file_with_password, pack_with_options, read_archive_index_with_password,
    unpack_all_with_progress, verify_archive_integrity_with_progress, PackOptions, ProgressTracker,
};
use crate::router::CompressionProfile;
use crate::shell::{register_windows_context_menu, unregister_windows_context_menu};
use eframe::egui;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum StartupAction {
    OpenOnly(PathBuf),
    AutoPack(PathBuf),
    AutoUnpack(PathBuf),
}

enum JobResult {
    Packed(PathBuf, Result<SeekableIndexFooter, String>, f64),
    Unpacked(PathBuf, Result<(SeekableIndexFooter, usize), String>, f64),
    ZipExtracted(PathBuf, Result<(u64, u64), String>, f64),
    Verified(Result<(u64, u64, usize), String>, f64),
}

struct BackgroundJob {
    label: String,
    tracker: Arc<ProgressTracker>,
    rx: Receiver<JobResult>,
    started: Instant,
}

pub struct NxzStudioApp {
    input_path: String,
    output_path: String,
    selected_profile: CompressionProfile,
    password: String,
    enable_ecc: bool,
    status_log: String,
    loaded_footer: Option<SeekableIndexFooter>,
    loaded_archive_path: Option<PathBuf>,
    single_file_filter: String,
    active_job: Option<BackgroundJob>,
}

impl Default for NxzStudioApp {
    fn default() -> Self {
        Self {
            input_path: String::new(),
            output_path: String::new(),
            selected_profile: CompressionProfile::Balanced,
            password: String::new(),
            enable_ecc: false,
            status_log: "Bereit. Ziehe eine Datei, einen Ordner, ein .nxz- oder .zip-Archiv per Drag & Drop in dieses Fenster.".to_string(),
            loaded_footer: None,
            loaded_archive_path: None,
            single_file_filter: String::new(),
            active_job: None,
        }
    }
}

impl NxzStudioApp {
    pub fn new_with_action(_cc: &eframe::CreationContext<'_>, action: Option<StartupAction>) -> Self {
        let mut app = Self::default();
        if let Some(act) = action {
            match act {
                StartupAction::OpenOnly(path) => {
                    app.input_path = path.to_string_lossy().to_string();
                    if has_ext(&path, "nxz") {
                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
                        app.output_path = path
                            .parent()
                            .unwrap_or(&path)
                            .join(format!("{stem}_extracted"))
                            .to_string_lossy()
                            .to_string();
                        app.load_index_only();
                    } else if has_ext(&path, "zip") {
                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unzipped");
                        app.output_path = path
                            .parent()
                            .unwrap_or(&path)
                            .join(format!("{stem}_extracted"))
                            .to_string_lossy()
                            .to_string();
                        app.status_log = format!(
                            "ZIP-Archiv geladen: '{}'. Klicke auf 'KOMPLETT ENTPACKEN' fuer die native Extraktion.",
                            app.input_path
                        );
                    } else {
                        app.output_path = format!("{}.nxz", app.input_path);
                        app.status_log = format!("Quelle geladen: {}", app.input_path);
                    }
                }
                StartupAction::AutoUnpack(path) => {
                    app.input_path = path.to_string_lossy().to_string();
                    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
                    app.output_path = path
                        .parent()
                        .unwrap_or(&path)
                        .join(format!("{stem}_extracted"))
                        .to_string_lossy()
                        .to_string();
                    if has_ext(&path, "nxz") {
                        app.load_index_only();
                    }
                    app.run_unpack_all();
                }
                StartupAction::AutoPack(path) => {
                    app.input_path = path.to_string_lossy().to_string();
                    app.output_path = format!("{}.nxz", app.input_path);
                    app.selected_profile = CompressionProfile::Balanced;
                    app.enable_ecc = false;
                    app.run_pack();
                }
            }
        }
        app
    }
}

fn build_app_icon() -> egui::IconData {
    const W: usize = 64;
    const H: usize = 64;
    let mut rgba = Vec::with_capacity(W * H * 4);
    for y_i in 0..H {
        let y = y_i as f32;
        for x_i in 0..W {
            let x = x_i as f32;
            let cx = 31.5f32;
            let cy = 31.5f32;
            let dx = (x - cx).abs();
            let dy = (y - cy).abs();
            let corner_r = 12.0f32;
            let half = 28.0f32;
            let qx = (dx - (half - corner_r)).max(0.0);
            let qy = (dy - (half - corner_r)).max(0.0);
            let dist = (qx * qx + qy * qy).sqrt() - corner_r;

            if dist > 1.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let is_border = dist > -2.5;
            let nx = (x - 32.0) / 20.0;
            let ny = (y - 32.0) / 20.0;
            let in_upper_bolt = ny >= -0.75 && ny <= 0.10 && nx >= -0.45 - ny * 0.4 && nx <= 0.15 - ny * 0.55;
            let in_lower_bolt = ny >= -0.10 && ny <= 0.75 && nx >= -0.15 - ny * 0.55 && nx <= 0.45 - ny * 0.4;
            let in_bolt = in_upper_bolt || in_lower_bolt;

            let (r, g, b) = if in_bolt {
                (255u8, 215u8, 40u8)
            } else if is_border {
                (0u8, 210u8, 255u8)
            } else {
                let grad = ((y / 64.0) * 28.0) as u8;
                (14u8.saturating_add(grad / 2), 26u8.saturating_add(grad), 58u8.saturating_add(grad))
            };
            let alpha = if dist > 0.0 {
                ((1.0 - dist) * 255.0) as u8
            } else {
                255u8
            };
            rgba.extend_from_slice(&[r, g, b, alpha]);
        }
    }
    egui::IconData {
        rgba,
        width: W as u32,
        height: H as u32,
    }
}

pub fn launch_desktop_gui() -> Result<(), eframe::Error> {
    launch_desktop_gui_with_action(None)
}

pub fn launch_desktop_gui_with_action(action: Option<StartupAction>) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_drag_and_drop(true)
            .with_icon(Arc::new(build_app_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "NXZ Studio v2.2 — Standalone High-Speed Archiver",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(NxzStudioApp::new_with_action(cc, action))
        }),
    )
}

pub struct NxzSetupWizardApp {
    create_desktop_shortcut: bool,
    create_start_menu: bool,
    register_shell: bool,
    installed_exe_path: Option<PathBuf>,
    status_message: String,
    is_error: bool,
}

impl Default for NxzSetupWizardApp {
    fn default() -> Self {
        Self {
            create_desktop_shortcut: true,
            create_start_menu: true,
            register_shell: true,
            installed_exe_path: None,
            status_message: String::new(),
            is_error: false,
        }
    }
}

impl eframe::App for NxzSetupWizardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("⚡ NXZ Studio v2.2 — Offizieller Windows-Setup-Assistent");
            ui.add_space(4.0);
            ui.label(
                "High-Speed Smart Archiver mit Instant-Seek (< 250 ms), BLAKE3-Deduplizierung, \
                 Smart-Media-Bypass (> 1.000 MB/s), XChaCha20-Poly1305 AEAD & Reed-Solomon ECC.",
            );
            ui.separator();
            ui.add_space(6.0);

            let target_dir = default_install_dir();
            ui.horizontal(|ui| {
                ui.strong("📂 Zielverzeichnis:");
                ui.monospace(target_dir.to_string_lossy().to_string());
            });
            ui.add_space(10.0);

            ui.strong("🔧 Installations-Optionen:");
            ui.add_space(4.0);
            ui.checkbox(
                &mut self.create_desktop_shortcut,
                "Desktop-Verknüpfung erstellen (NXZ Studio)",
            );
            ui.checkbox(
                &mut self.create_start_menu,
                "Im Windows-Startmenü & in der Windows-Suche eintragen",
            );
            ui.checkbox(
                &mut self.register_shell,
                "Windows-Rechtsklick-Menü & .nxz-Doppelklick verknüpfen",
            );

            ui.add_space(14.0);
            let install_btn = egui::Button::new(
                egui::RichText::new("🚀 JETZT INSTALLIEREN (1-Klick Setup)")
                    .size(16.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            )
            .fill(egui::Color32::from_rgb(0, 125, 215))
            .min_size(egui::vec2(ui.available_width(), 42.0));

            if ui.add(install_btn).clicked() {
                match install_application(
                    self.create_desktop_shortcut,
                    self.create_start_menu,
                    self.register_shell,
                ) {
                    Ok(exe_path) => {
                        self.installed_exe_path = Some(exe_path);
                        self.status_message =
                            "✅ NXZ Studio v2.2 wurde erfolgreich auf deinem PC installiert!".to_string();
                        self.is_error = false;
                    }
                    Err(e) => {
                        self.status_message = format!("❌ Installation fehlgeschlagen: {e}");
                        self.is_error = true;
                    }
                }
            }

            if !self.status_message.is_empty() {
                ui.add_space(10.0);
                let color = if self.is_error {
                    egui::Color32::from_rgb(255, 95, 95)
                } else {
                    egui::Color32::from_rgb(70, 230, 110)
                };
                ui.label(egui::RichText::new(&self.status_message).strong().color(color));
            }

            if let Some(ref exe_path) = self.installed_exe_path.clone() {
                ui.add_space(8.0);
                let launch_btn = egui::Button::new(
                    egui::RichText::new("⚡ NXZ Studio jetzt starten & Setup schließen")
                        .size(14.5)
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(28, 155, 75))
                .min_size(egui::vec2(ui.available_width(), 36.0));

                if ui.add(launch_btn).clicked() {
                    let _ = std::process::Command::new(exe_path).spawn();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::RIGHT), |ui| {
                ui.horizontal(|ui| {
                    if ui.button("🗑 Bestehende Installation deinstallieren").clicked() {
                        match uninstall_application() {
                            Ok(()) => {
                                self.installed_exe_path = None;
                                self.status_message =
                                    "✅ Bestehende Installation, Verknüpfungen und Registry-Einträge wurden entfernt."
                                        .to_string();
                                self.is_error = false;
                            }
                            Err(e) => {
                                self.status_message = format!("❌ Deinstallation fehlgeschlagen: {e}");
                                self.is_error = true;
                            }
                        }
                    }
                });
            });
        });
    }
}

pub fn launch_setup_wizard_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 440.0])
            .with_resizable(false)
            .with_icon(Arc::new(build_app_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "⚡ NXZ Studio v2.2 — Offizieller Windows-Setup-Assistent",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(NxzSetupWizardApp::default())
        }),
    )
}

struct NxzUninstallNoticeApp {
    message: String,
    is_error: bool,
}

impl eframe::App for NxzUninstallNoticeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🗑 NXZ Studio v2.2 — Deinstallation");
            ui.separator();
            ui.add_space(12.0);
            let color = if self.is_error {
                egui::Color32::from_rgb(255, 95, 95)
            } else {
                egui::Color32::from_rgb(70, 230, 110)
            };
            ui.label(egui::RichText::new(&self.message).strong().color(color));
            ui.add_space(18.0);
            if ui.button("Schließen").clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }
}

pub fn launch_uninstall_notice_gui(result: Result<(), String>) -> Result<(), eframe::Error> {
    let (message, is_error) = match result {
        Ok(()) => (
            "✅ NXZ Studio v2.2 wurde vollständig von deinem PC deinstalliert (Programmdateien, Verknüpfungen & Kontextmenü entfernt)."
                .to_string(),
            false,
        ),
        Err(e) => (format!("❌ Fehler bei der Deinstallation: {e}"), true),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 200.0])
            .with_resizable(false)
            .with_icon(Arc::new(build_app_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "NXZ Studio v2.2 — Deinstallation",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Box::new(NxzUninstallNoticeApp { message, is_error })
        }),
    )
}

pub fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn has_ext(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

fn sort_files_by_size(footer: &mut SeekableIndexFooter) {
    footer.files.sort_by(|a, b| {
        b.original_size
            .cmp(&a.original_size)
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
}

impl eframe::App for NxzStudioApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_background_job();
        let busy = self.active_job.is_some();
        if busy {
            ctx.request_repaint_after(Duration::from_millis(30));
        }

        if !busy {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if let Some(first) = dropped.first() {
                if let Some(ref path) = first.path {
                    self.set_source(path.clone());
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("⚡ NXZ Studio v2.2 — Standalone High-Speed Smart Archiver");
            ui.label("FOT-2 • Office-Turbo • BLAKE3-Deduplizierung • XChaCha20-Poly1305 AEAD • Reed-Solomon • Atomares Schreiben");
            ui.separator();

            ui.add_enabled_ui(!busy, |ui| {
                egui::Grid::new("path_grid")
                    .num_columns(3)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("📂 Quelle (Datei / Ordner / .nxz / .zip):");
                        ui.add(egui::TextEdit::singleline(&mut self.input_path).desired_width(520.0));
                        ui.horizontal(|ui| {
                            if ui.button("Datei...").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_file() {
                                    self.set_source(p);
                                }
                            }
                            if ui.button("Ordner...").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                    self.set_source(p);
                                }
                            }
                        });
                        ui.end_row();

                        ui.label("🎯 Ziel (Archiv / Zielordner):");
                        ui.add(egui::TextEdit::singleline(&mut self.output_path).desired_width(520.0));
                        if ui.button("Ziel waehlen...").clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                self.output_path = p.to_string_lossy().to_string();
                            }
                        }
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("🚀 Kompressions-Profil:");
                    ui.radio_value(&mut self.selected_profile, CompressionProfile::Turbo, "Turbo");
                    ui.radio_value(&mut self.selected_profile, CompressionProfile::Balanced, "Balanced (FOT-2 + Zstd-9)");
                    ui.radio_value(&mut self.selected_profile, CompressionProfile::Ultra, "Ultra (FOT-2 + LZMA2)");
                });
                ui.horizontal(|ui| {
                    ui.label("🔐 Tresor-Passwort (optional):");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(220.0));
                    ui.add_space(16.0);
                    ui.checkbox(&mut self.enable_ecc, "[ECC] Reed-Solomon Selbstheilung");
                });

                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("📦 JETZT PACKEN (.nxz erstellen)").clicked() {
                        self.run_pack();
                    }
                    if ui.button("📂 KOMPLETT ENTPACKEN").clicked() {
                        self.run_unpack_all();
                    }
                    if ui.button("✔ ARCHIV AUF ECHTHEIT PRUEFEN").clicked() {
                        self.run_verify_integrity();
                    }
                    if ui.button("📂 Ziel im Explorer oeffnen").clicked() {
                        self.open_target_in_explorer();
                    }
                    if ui.button("🔍 ARCHIV-INDEX LADEN").clicked() {
                        let p = PathBuf::from(self.input_path.trim());
                        self.inspect_loaded_archive(p);
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .button("🚀 Als festes Windows-Programm installieren (Setup)")
                        .clicked()
                    {
                        match install_application(true, true, true) {
                            Ok(installed_exe) => {
                                self.status_log = format!(
                                    "✅ NXZ Studio v2.2 fest installiert unter '{}' (inkl. Desktop, Startmenü & Rechtsklick)!",
                                    installed_exe.display()
                                );
                            }
                            Err(err) => self.status_log = format!("❌ {err}"),
                        }
                    }
                    if ui.button("[Shell] Windows-Rechtsklick-Menue aktivieren").clicked() {
                        match register_windows_context_menu() {
                            Ok(msg) => self.status_log = msg,
                            Err(err) => self.status_log = err,
                        }
                    }
                    if ui.button("Aus Rechtsklick entfernen").clicked() {
                        match unregister_windows_context_menu() {
                            Ok(msg) => self.status_log = msg,
                            Err(err) => self.status_log = err,
                        }
                    }
                });
            });

            if let Some(job) = &self.active_job {
                ui.add_space(8.0);
                ui.separator();
                let processed = job.tracker.processed_bytes.load(Ordering::Relaxed);
                let total = job.tracker.total_bytes.load(Ordering::Relaxed);
                let fraction = if total > 0 {
                    (processed as f32 / total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let elapsed = job.started.elapsed().as_secs_f64().max(0.001);
                let mbs = (processed as f64 / (1024.0 * 1024.0)) / elapsed;
                let current_item = job
                    .tracker
                    .current_item
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or_default();

                ui.label(egui::RichText::new(format!("⏳ {} läuft ...", job.label)).strong());
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .show_percentage()
                        .animate(true)
                        .desired_width(ui.available_width()),
                );
                ui.label(format!(
                    "{:.1} / {:.1} MB  •  {:.1} MB/s  •  {:.1} s  •  Aktuell: {}",
                    processed as f64 / (1024.0 * 1024.0),
                    total as f64 / (1024.0 * 1024.0),
                    mbs,
                    elapsed,
                    current_item
                ));
                let cancel_btn = egui::Button::new(
                    egui::RichText::new("⛔ ABBRECHEN").strong().color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(190, 30, 30));
                if ui.add(cancel_btn).clicked() {
                    job.tracker.cancel_requested.store(true, Ordering::SeqCst);
                }
            }

            ui.add_space(8.0);
            ui.separator();
            ui.label(egui::RichText::new(&self.status_log).strong());
            ui.separator();

            if let Some(footer) = self.loaded_footer.clone() {
                ui.label(format!(
                    "📊 Archiv: {} Dateien in {} Bloecken | Original: {} | Gespeichert: {} | Verschluesselt: {} | ECC: {}",
                    footer.total_files,
                    footer.blocks.len(),
                    format_size(footer.total_uncompressed_bytes),
                    format_size(footer.total_stored_bytes),
                    if footer.encrypted { "JA" } else { "NEIN" },
                    if footer.ecc_enabled { "AKTIV" } else { "AUS" }
                ));
                ui.horizontal(|ui| {
                    ui.label("🔎 Dateisuche im Archiv:");
                    ui.text_edit_singleline(&mut self.single_file_filter);
                });

                let filter = self.single_file_filter.to_lowercase();
                let mut clicked_path: Option<String> = None;
                egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                    egui::Grid::new("archive_files_table")
                        .striped(true)
                        .min_col_width(80.0)
                        .show(ui, |ui| {
                            ui.strong("Relativer Dateipfad");
                            ui.strong("Originalgroesse");
                            ui.strong("Block #");
                            ui.strong("Entropie");
                            ui.strong("Direkt-Zugriff");
                            ui.end_row();
                            for f in &footer.files {
                                if !filter.is_empty() && !f.relative_path.to_lowercase().contains(&filter) {
                                    continue;
                                }
                                ui.label(&f.relative_path);
                                ui.label(format_size(f.original_size));
                                ui.label(format!("#{}", f.block_id));
                                ui.label(format!("{:.2} bpb", f.shannon_entropy_bpb));
                                if ui.add_enabled(!busy, egui::Button::new("⚡ Sofort extrahieren")).clicked() {
                                    clicked_path = Some(f.relative_path.clone());
                                }
                                ui.end_row();
                            }
                        });
                });
                if let Some(p) = clicked_path {
                    self.run_single_file_seek(&p);
                }
            }
        });
    }
}

impl NxzStudioApp {
    fn set_source(&mut self, path: PathBuf) {
        self.input_path = path.to_string_lossy().to_string();
        if has_ext(&path, "nxz") {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unpacked");
            self.output_path = path
                .parent()
                .unwrap_or(&path)
                .join(format!("{stem}_extracted"))
                .to_string_lossy()
                .to_string();
            self.inspect_loaded_archive(path);
        } else if has_ext(&path, "zip") {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unzipped");
            self.output_path = path
                .parent()
                .unwrap_or(&path)
                .join(format!("{stem}_extracted"))
                .to_string_lossy()
                .to_string();
            self.status_log = format!(
                "ZIP-Archiv geladen: '{}'. Klicke auf 'KOMPLETT ENTPACKEN' fuer die native Extraktion.",
                self.input_path
            );
        } else {
            self.output_path = format!("{}.nxz", self.input_path);
            self.status_log = format!("Quelle geladen: {}", self.input_path);
        }
    }

    fn password_opt(&self) -> Option<String> {
        if self.password.is_empty() {
            None
        } else {
            Some(self.password.clone())
        }
    }

    fn resolve_archive_path(&self) -> PathBuf {
        let input_candidate = PathBuf::from(self.input_path.trim());
        if input_candidate.is_file() && (has_ext(&input_candidate, "nxz") || has_ext(&input_candidate, "zip")) {
            input_candidate
        } else if let Some(ref loaded) = self.loaded_archive_path {
            loaded.clone()
        } else {
            PathBuf::from(self.output_path.trim())
        }
    }

    fn resolve_output_dir(&self, archive: &Path, suffix: &str) -> PathBuf {
        let raw_out = self.output_path.trim();
        let out_candidate = PathBuf::from(raw_out);
        let lower = raw_out.to_lowercase();
        if raw_out.is_empty() || lower.ends_with(".nxz") || lower.ends_with(".zip") || out_candidate.is_file() {
            let stem = archive.file_stem().and_then(|s| s.to_str()).unwrap_or("nxz");
            archive.parent().unwrap_or(archive).join(format!("{stem}_{suffix}"))
        } else {
            out_candidate
        }
    }

    fn start_job<F>(&mut self, label: &str, work: F)
    where
        F: FnOnce(Arc<ProgressTracker>) -> JobResult + Send + 'static,
    {
        if self.active_job.is_some() {
            return;
        }
        let tracker = ProgressTracker::new();
        let (tx, rx) = channel();
        let worker_tracker = tracker.clone();
        std::thread::spawn(move || {
            let result = work(worker_tracker);
            let _ = tx.send(result);
        });
        self.status_log = format!("⏳ {label} gestartet ...");
        self.active_job = Some(BackgroundJob {
            label: label.to_string(),
            tracker,
            rx,
            started: Instant::now(),
        });
    }

    fn poll_background_job(&mut self) {
        let Some(job) = &self.active_job else { return };
        let result = match job.rx.try_recv() {
            Ok(r) => r,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.status_log = "❌ Hintergrund-Job unerwartet beendet.".to_string();
                self.active_job = None;
                return;
            }
        };
        self.active_job = None;

        match result {
            JobResult::Packed(dst, Ok(mut footer), elapsed) => {
                sort_files_by_size(&mut footer);
                let mbs = (footer.total_uncompressed_bytes as f64 / (1024.0 * 1024.0)) / elapsed;
                let ratio = if footer.total_uncompressed_bytes > 0 {
                    (footer.total_stored_bytes as f64 / footer.total_uncompressed_bytes as f64) * 100.0
                } else {
                    100.0
                };
                self.status_log = format!(
                    "✅ PACKEN ERFOLGREICH: {} Dateien ({} -> {}, {:.1}%) in {:.3} s ({:.1} MB/s)",
                    footer.total_files,
                    format_size(footer.total_uncompressed_bytes),
                    format_size(footer.total_stored_bytes),
                    ratio,
                    elapsed,
                    mbs
                );
                self.loaded_archive_path = Some(dst);
                self.loaded_footer = Some(footer);
            }
            JobResult::Packed(_, Err(e), _) => {
                self.status_log = format!("❌ Packen beendet: {e} (keine halbfertige .nxz-Datei hinterlassen)");
            }
            JobResult::Unpacked(out_dir, Ok((footer, healed)), elapsed) => {
                let mbs = (footer.total_uncompressed_bytes as f64 / (1024.0 * 1024.0)) / elapsed;
                let heal_msg = if healed > 0 {
                    format!(" | [ECC] {healed} defekte Shards repariert")
                } else {
                    String::new()
                };
                self.status_log = format!(
                    "✅ ENTPACKEN & BLAKE3-PRUEFUNG ERFOLGREICH: {} Dateien ({}) in {:.3} s ({:.1} MB/s) nach '{}'{}",
                    footer.total_files,
                    format_size(footer.total_uncompressed_bytes),
                    elapsed,
                    mbs,
                    out_dir.display(),
                    heal_msg
                );
            }
            JobResult::Unpacked(_, Err(e), _) => {
                self.status_log = format!("❌ Entpacken beendet: {e}");
            }
            JobResult::ZipExtracted(out_dir, Ok((files, bytes)), elapsed) => {
                self.status_log = format!(
                    "✅ ZIP ENTPACKT: {} Dateien ({}) in {:.3} s nach '{}'",
                    files,
                    format_size(bytes),
                    elapsed,
                    out_dir.display()
                );
            }
            JobResult::ZipExtracted(_, Err(e), _) => {
                self.status_log = format!("❌ ZIP-Entpacken fehlgeschlagen: {e}");
            }
            JobResult::Verified(Ok((files, bytes, _healed)), elapsed) => {
                self.status_log = format!(
                    "✅ ECHTHEITS-ZERTIFIKAT: Alle {} Dateien ({}) wurden real aus dem Archiv entpackt und Bit fuer Bit per BLAKE3 verifiziert (0 Fehler)! [{:.2} s]",
                    files,
                    format_size(bytes),
                    elapsed
                );
            }
            JobResult::Verified(Err(e), _) => {
                self.status_log = format!("❌ Echtheits-Pruefung beendet: {e}");
            }
        }
    }

    fn run_pack(&mut self) {
        let src = PathBuf::from(self.input_path.trim());
        let dst = if self.output_path.trim().is_empty() {
            PathBuf::from(format!("{}.nxz", self.input_path.trim()))
        } else {
            PathBuf::from(self.output_path.trim())
        };
        let profile = self.selected_profile;
        let password = self.password_opt();
        let enable_ecc = self.enable_ecc;

        self.start_job("Packen", move |tracker| {
            let start = Instant::now();
            let opts = PackOptions {
                profile,
                password,
                enable_ecc,
                progress: Some(tracker),
            };
            let res = pack_with_options(&src, &dst, &opts).map_err(|e| e.to_string());
            JobResult::Packed(dst, res, start.elapsed().as_secs_f64().max(0.0001))
        });
    }

    fn run_unpack_all(&mut self) {
        let archive = self.resolve_archive_path();
        let out_dir = self.resolve_output_dir(&archive, "extracted");

        if has_ext(&archive, "zip") {
            self.start_job("ZIP-Entpacken", move |tracker| {
                tracker.set_item(archive.to_string_lossy().to_string());
                let start = Instant::now();
                let res = extract_standard_zip(&archive, &out_dir).map_err(|e| e.to_string());
                JobResult::ZipExtracted(out_dir, res, start.elapsed().as_secs_f64().max(0.0001))
            });
            return;
        }

        let password = self.password_opt();
        self.start_job("Entpacken", move |tracker| {
            let start = Instant::now();
            let res = unpack_all_with_progress(&archive, &out_dir, password.as_deref(), Some(tracker.as_ref()))
                .map_err(|e| e.to_string());
            JobResult::Unpacked(out_dir, res, start.elapsed().as_secs_f64().max(0.0001))
        });
    }

    fn run_verify_integrity(&mut self) {
        let archive = self.resolve_archive_path();
        let password = self.password_opt();
        self.start_job("Echtheits-Pruefung", move |tracker| {
            let start = Instant::now();
            let res = verify_archive_integrity_with_progress(&archive, password.as_deref(), Some(tracker.as_ref()))
                .map_err(|e| e.to_string());
            JobResult::Verified(res, start.elapsed().as_secs_f64().max(0.0001))
        });
    }

    pub fn load_index_only(&mut self) {
        let p = PathBuf::from(self.input_path.trim());
        self.inspect_loaded_archive(p);
    }

    fn inspect_loaded_archive(&mut self, archive: PathBuf) {
        let pw = self.password_opt();
        match read_archive_index_with_password(&archive, pw.as_deref()) {
            Ok((_hdr, mut footer, _)) => {
                sort_files_by_size(&mut footer);
                self.status_log = format!(
                    "✅ Index geladen: {} Dateien in {} Seekable Micro-Blocks bereit.",
                    footer.total_files,
                    footer.blocks.len()
                );
                self.loaded_archive_path = Some(archive);
                self.loaded_footer = Some(footer);
            }
            Err(e) => {
                self.status_log = format!("🔒 Index konnte nicht gelesen werden: {e}");
            }
        }
    }

    fn run_single_file_seek(&mut self, rel_path: &str) {
        let Some(archive) = self.loaded_archive_path.clone() else { return };
        let out_dir = self.resolve_output_dir(&archive, "single_extracted");
        let pw = self.password_opt();
        let start = Instant::now();
        match extract_single_file_with_password(&archive, rel_path, &out_dir, pw.as_deref()) {
            Ok(saved_path) => {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.status_log = format!(
                    "⚡ INSTANT-SEEK ({:.2} ms): '{}' extrahiert nach '{}'",
                    ms,
                    rel_path,
                    saved_path.display()
                );
            }
            Err(e) => {
                self.status_log = format!("❌ Fehler bei Einzeldatei-Extraktion: {e}");
            }
        }
    }

    fn open_target_in_explorer(&mut self) {
        let out_candidate = PathBuf::from(self.output_path.trim());
        let target = if !self.output_path.trim().is_empty() && out_candidate.exists() {
            out_candidate
        } else if let Some(ref archive) = self.loaded_archive_path {
            archive.clone()
        } else {
            PathBuf::from(self.input_path.trim())
        };

        if target.is_file() {
            let _ = std::process::Command::new("explorer")
                .arg(format!("/select,{}", target.display()))
                .spawn();
            self.status_log = format!("📂 Im Windows Explorer markiert: '{}'", target.display());
        } else if target.is_dir() {
            let _ = std::process::Command::new("explorer").arg(&target).spawn();
            self.status_log = format!("📂 Ordner im Windows Explorer geoeffnet: '{}'", target.display());
        } else if let Some(parent) = target.parent().filter(|p| p.exists()) {
            let _ = std::process::Command::new("explorer").arg(parent).spawn();
            self.status_log = format!("📂 Ordner im Windows Explorer geoeffnet: '{}'", parent.display());
        } else {
            self.status_log = "❌ Kein existierendes Ziel zum Oeffnen gefunden.".to_string();
        }
    }
}
