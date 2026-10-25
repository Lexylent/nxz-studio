# ⚡ NXZ Studio v2.2 — High-Speed Smart Archiver for Windows

## 📥 Direkt-Download für Windows 10 & 11 (Keine Programmierkenntnisse nötig)
👉 **[Hier klicken: NXZ-Studio-Setup.exe herunterladen (v2.2.0 — 1-Klick Windows-Installer)](../../releases/latest/download/NXZ-Studio-Setup.exe)**

![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(x64)-0078D6?style=for-the-badge&logo=windows)
![Language](https://img.shields.io/badge/Built%20with-Rust%202021-DEA584?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/License-MIT-2EA44F?style=for-the-badge)
![Version](https://img.shields.io/badge/Release-v2.2.0-FFD700?style=for-the-badge)

**FOT-2 Dynamic Tokenizer • Office-Unfold • BLAKE3 Content Deduplication • 16 MB Seekable Micro-Blocks • XChaCha20-Poly1305 AEAD • Reed-Solomon Self-Healing (ECC) • Native GUI & Windows Explorer Shell Integration**

---

## 🇩🇪 Deutsch — Überblick & Schnelleinstieg

### Warum NXZ Studio? (Das Problem mit klassischen Packern)

Klassische Archivierer wie **7-Zip** oder **WinRAR** zwingen Nutzer seit Jahrzehnten zu einem schmerzhaften Kompromiss: Entweder man nutzt **Solid-Archive** für gute Kompression (muss dann aber bei einem 10-GB-Archiv minutenlang warten, nur um eine einzige Datei herauszuholen), oder man verzichtet auf Solid-Kompression und verschenkt enorm viel Speicherplatz. Zudem verschwenden klassische Packer oft Minuten damit, bereits komprimierte `.mp4`-Videos oder `.jpg`-Fotos erneut durch langsame LZMA-Pipelines zu pressen.

**NXZ Studio v2.2** löst diese Probleme durch 5 architektonische Alleinstellungsmerkmale:

1. **⚡ Instant-Seek (`< 5 ms – 250 ms`) trotz hoher Kompression:**
   Statt starrer Solid-Blöcke arbeitet NXZ mit **16-MB-Seekable-Micro-Blocks** und einem komprimierten `SeekableIndexFooter`. Einzelne Dateien lassen sich aus einem 10-GB-Archiv sofort per Mausklick extrahieren, ohne das gesamte Archiv entpacken zu müssen.
2. **🧬 Automatische BLAKE3-Deduplizierung (Gamechanger für Video-Creators, Musiker & Entwickler):**
   Erkennt identische Dateien sowie identische 16-MB-Chunks über alle Unterordner hinweg (z. B. `renders/` und `upload_package/`) anhand ihres kryptografischen 256-Bit-`BLAKE3`-Hashes und speichert sie physisch nur ein einziges Mal.
3. **🧠 Intelligenter Entropie- & Magic-Byte-Router (`FOT-2 + Zstd / LZMA2 + x86-BCJ`):**
   Analysiert jede Datei in Echtzeit (Shannon-Entropie + Header-Signatur). Quellcode, Text, Office-Dokumente (`.docx`, `.xlsx`, `.pptx` via Lossless Deflate Unfolding) und ausführbare Binärdateien (`.exe`, `.dll` via `x86-BCJ`-Filter) werden maximal komprimiert, während bereits komprimierte Medien (`.mp4`, `.mkv`, `.jpg`) ohne Zeitverlust mit **> 1.000 MB/s** per Smart-Bypass durchgeleitet werden.
4. **🔐 Kryptografischer AEAD-Tresor & Echtheits-Zertifikat:**
   Optionale militärstarke Verschlüsselung mit **`Argon2id`** (Key Derivation) + **`XChaCha20-Poly1305`** (Authenticated Encryption) sowie integrierter **256-Bit-`BLAKE3`-Echtheitsprüfer** für jede einzelne Datei und jeden Block.
5. **🛡️ Optionale Reed-Solomon-Selbstheilung (ECC):**
   Schützt Archive auf Wunsch vor physischen Speicherfehlern (*Bit-Rot* auf USB-Sticks, externen SSDs oder NAS-Laufwerken) und repariert beschädigte Sektoren vollautomatisch beim Entpacken.

---

### 📊 Reale Benchmark-Tabelle (Echte Messwerte)

| Szenario / Datensatz | Ausgangsgröße | NXZ Archivgröße (Quote) | Dauer / Durchsatz | Aktive Pipeline-Technologien |
| :--- | :--- | :--- | :--- | :--- |
| **Creator Video-Projekt** *(68 Dateien, MP4-Renders & Uploads)* | **1,09 GB** | **365,7 MB (33,5 %)** | **0,87 s (1.197 MB/s)** | BLAKE3-Deduplizierung + Smart Media-Bypass |
| **Rust/Windows Compiler-Projekt** *(3.340 Dateien)* | **1,06 GB** | **146,2 MB (13,8 %)** | Multi-Core Rayon | x86-BCJ + Dynamic FOT-2 + LZMA2 |
| **Einzeldatei-Direktzugriff** *(125 MB Video mitten aus 1,09-GB-Archiv)* | **125,0 MB** | Direkt-Extraktion | **235 ms (0,23 s)** | Seekable Index Footer + BLAKE3-Verifikation |

---

### 🚀 1-Klick-Installation für Windows (Kein Terminal nötig)

1. **`NXZ-Studio-Setup.exe` herunterladen:** Lade unter [**Releases**](../../releases) die Datei `NXZ-Studio-Setup.exe` herunter.
2. **Doppelklicken & *Jetzt installieren* wählen:** Der grafische Windows-Setup-Assistent installiert NXZ Studio sauber nach `%LOCALAPPDATA%\Programs\NXZ Studio`, legt eine Desktop- und Startmenü-Verknüpfung an und trägt das Programm ordentlich in die Windows-Systemsteuerung (*Installierte Apps*) ein.
3. **Sofort loslegen:**
   - **Doppelklick auf jede `.nxz`-Datei** im Windows Explorer öffnet sofort NXZ Studio und zeigt alle enthaltenen Dateien übersichtlich an.
   - **Rechtsklick auf Dateien/Ordner** -> `Mit NXZ packen (Balanced)` erstellt das `.nxz`-Archiv live mit sichtbarem Fortschrittsbalken.
   - **Rechtsklick auf `.nxz`-Archive** -> `NXZ-Archiv hier entpacken` entpackt und prüft alle Dateien per `BLAKE3`.
   - Auch klassische **`.zip`-Archive** (inkl. Streaming-Flag `0x08`) können direkt in NXZ Studio geöffnet und entpackt werden.

---

### 💻 CLI-Dokumentation & Build from Source

Neben der nativen Desktop-GUI enthält dieselbe Binary eine vollwertige Kommandozeilen-Schnittstelle (dank `AttachConsole` Dual-Subsystem):

```powershell
# Grafische Oberfläche starten
nxz.exe

# Grafischen Setup-Assistenten öffnen
nxz.exe --setup

# Ordner oder Datei packen (Profile: turbo | balanced | ultra)
nxz.exe pack "C:\Projekte\MeinOrdner" "C:\Backup\MeinOrdner.nxz" --profile balanced

# Mit Passwort (XChaCha20-Poly1305) und Reed-Solomon Selbstheilung (ECC) packen
nxz.exe pack "C:\Tresor" "C:\Backup\Tresor.nxz" --profile ultra --password "MeinGeheimesPasswort!" --ecc

# Archivinhalt auflisten
nxz.exe list "C:\Backup\MeinOrdner.nxz"

# Komplettes Archiv entpacken & per BLAKE3 verifizieren
nxz.exe unpack "C:\Backup\MeinOrdner.nxz" "C:\Restore"

# Einzelne Datei per Instant-Seek (< 250 ms) aus großem Archiv extrahieren
nxz.exe extract-file "C:\Backup\MeinOrdner.nxz" "renders/clip_01.mp4" "C:\Restore"
```

#### Aus dem Quellcode kompilieren (Rust 1.75+)

```powershell
git clone https://github.com/Lexylent/nxz-studio.git
cd nxz-studio
cargo test --release
cargo build --release
```

---

## 🌍 English — Overview & Documentation

### Why NXZ Studio? (The Problem with Legacy Archivers)

Traditional archivers like **7-Zip** and **WinRAR** force users into an outdated trade-off: either use **solid archives** for strong compression (forcing you to wait minutes scanning gigabytes just to extract a single file), or disable solid compression and waste massive disk space. Furthermore, legacy tools often waste CPU cycles trying to re-compress already compressed `.mp4` videos or `.jpg` media.

**NXZ Studio v2.2** solves this with 5 core engineering innovations written in 100% memory-safe Rust:

1. **⚡ Instant-Seek (`< 5 ms – 250 ms`) with High Compression:**
   Instead of monolithic solid streams, NXZ groups files by data class into **16 MB Seekable Micro-Blocks** indexed by a Zstd-compressed `SeekableIndexFooter`. Extract any single file from a multi-gigabyte archive in milliseconds.
2. **🧬 Automatic BLAKE3 Deduplication (Built for Video Creators, Musicians & Developers):**
   Automatically detects identical files and 16 MB chunks across all subdirectories (e.g., `renders/` and `upload_package/`) via 256-bit `BLAKE3` hashing and stores them physically only once.
3. **🧠 Smart Entropy & Magic-Byte Router (`FOT-2 + Zstd / LZMA2 + x86-BCJ`):**
   Analyzes Shannon entropy and magic bytes in real time. Source code, structured text, Office documents (`.docx`, `.xlsx`, `.pptx` via lossless deflate unfolding), and native binaries (`.exe`, `.dll` via `x86-BCJ` call/jump filtering) achieve maximum compression, while pre-compressed media (`.mp4`, `.mkv`, `.jpg`) fly through at **> 1,000 MB/s** via zero-overhead passthrough.
4. **🔐 Cryptographic AEAD Vault & Authenticity Certificate:**
   Optional encryption powered by **`Argon2id`** + **`XChaCha20-Poly1305`** AEAD, paired with mandatory 256-bit **`BLAKE3`** integrity verification for every block and file.
5. **🛡️ Optional Reed-Solomon Self-Healing (ECC):**
   Protects critical backups against physical media corruption (*bit-rot* on flash drives or external disks) and automatically heals damaged shards during extraction.

---

### 📊 Real-World Benchmarks

| Workload / Dataset | Original Size | NXZ Archive Size (Ratio) | Time / Throughput | Active Pipeline Stages |
| :--- | :--- | :--- | :--- | :--- |
| **Creator Video Project** *(68 files, MP4 renders & uploads)* | **1.09 GB** | **365.7 MB (33.5%)** | **0.87 s (1,197 MB/s)** | BLAKE3 Deduplication + Smart Media Bypass |
| **Rust/Windows Compiler Project** *(3,340 files)* | **1.06 GB** | **146.2 MB (13.8%)** | Multi-Core Rayon | x86-BCJ + Dynamic FOT-2 + LZMA2 |
| **Single-File Instant Seek** *(125 MB video inside 1.09 GB archive)* | **125.0 MB** | Direct Seek Extraction | **235 ms (0.23 s)** | Seekable Index Footer + BLAKE3 Verification |

---

### 🚀 1-Click Installation for Windows (No Terminal Required)

1. **Download `NXZ-Studio-Setup.exe`:** Grab `NXZ-Studio-Setup.exe` from the [**Releases**](../../releases) page.
2. **Double-click & click *Install Now*:** The native graphical setup wizard installs NXZ Studio into `%LOCALAPPDATA%\Programs\NXZ Studio`, creates Desktop and Start Menu shortcuts, and registers the uninstaller in Windows *Installed Apps*.
3. **Use anywhere in Windows Explorer:**
   - **Double-click any `.nxz` archive** to open it immediately in NXZ Studio and browse/search all files.
   - **Right-click any file or folder** -> `Mit NXZ packen (Balanced)` to pack with a live progress bar.
   - **Right-click any `.nxz` archive** -> `NXZ-Archiv hier entpacken` to extract and verify all files.

---

### 🔍 SEO Keywords & GitHub Topics

`archiver` `compression` `rust` `zstd` `lzma2` `blake3` `deduplication` `windows-archiver` `7zip-alternative` `winrar-alternative` `reed-solomon` `xchacha20-poly1305` `seekable-archive` `egui` `high-speed-compression` `backup-tool` `bit-rot-protection`
