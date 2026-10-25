use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(windows)]
    {
        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
        let ico_path = out_dir.join("nxz_icon.ico");
        let rc_path = out_dir.join("nxz_icon.rc");
        let res_path = out_dir.join("nxz_icon.res");

        if write_nxz_ico(&ico_path).is_ok() {
            let escaped_ico = ico_path.to_string_lossy().replace('\\', "\\\\");
            let rc_content = format!("1 ICON \"{}\"\r\n", escaped_ico);
            if fs::write(&rc_path, rc_content).is_ok() {
                if let Some(rc_exe) = find_rc_exe() {
                    let status = Command::new(rc_exe)
                        .arg("/nologo")
                        .arg("/fo")
                        .arg(&res_path)
                        .arg(&rc_path)
                        .status();
                    if let Ok(s) = status {
                        if s.success() && res_path.exists() {
                            println!("cargo:rustc-link-arg-bins={}", res_path.display());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
fn find_rc_exe() -> Option<PathBuf> {
    if let Ok(output) = Command::new("where").arg("rc.exe").output() {
        if output.status.success() {
            if let Some(first) = String::from_utf8_lossy(&output.stdout).lines().next() {
                let p = PathBuf::from(first.trim());
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    let kits_root = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if let Ok(entries) = fs::read_dir(kits_root) {
        let mut versions: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        versions.reverse();
        for ver_dir in versions {
            let candidate = ver_dir.join("x64").join("rc.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn write_nxz_ico(path: &Path) -> std::io::Result<()> {
    const W: usize = 64;
    const H: usize = 64;
    let xor_size = W * H * 4;
    let and_size = (W * H) / 8;
    let dib_size = 40 + xor_size + and_size;

    let mut ico = Vec::with_capacity(22 + dib_size);

    // ICONDIR (6 bytes)
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);

    // ICONDIRENTRY (16 bytes)
    ico.push(W as u8);
    ico.push(H as u8);
    ico.push(0);
    ico.push(0);
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&(dib_size as u32).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());

    // BITMAPINFOHEADER (40 bytes)
    ico.extend_from_slice(&40u32.to_le_bytes());
    ico.extend_from_slice(&(W as i32).to_le_bytes());
    ico.extend_from_slice(&((H * 2) as i32).to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&32u16.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());
    ico.extend_from_slice(&((xor_size + and_size) as u32).to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0i32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());
    ico.extend_from_slice(&0u32.to_le_bytes());

    // Bottom-up BGRA pixels
    for y_inv in 0..H {
        let y = (H - 1 - y_inv) as f32;
        for x_i in 0..W {
            let x = x_i as f32;
            let (r, g, b, a) = render_icon_pixel(x, y);
            ico.push(b);
            ico.push(g);
            ico.push(r);
            ico.push(a);
        }
    }

    // AND mask (all 0 = use alpha channel)
    ico.resize(ico.len() + and_size, 0u8);

    fs::write(path, ico)
}

#[cfg(windows)]
fn render_icon_pixel(x: f32, y: f32) -> (u8, u8, u8, u8) {
    let cx = 31.5f32;
    let cy = 31.5f32;
    let dx = (x - cx).abs();
    let dy = (y - cy).abs();

    // Rounded square SDF
    let corner_r = 12.0f32;
    let half = 28.0f32;
    let qx = (dx - (half - corner_r)).max(0.0);
    let qy = (dy - (half - corner_r)).max(0.0);
    let dist = (qx * qx + qy * qy).sqrt() - corner_r;

    if dist > 1.0 {
        return (0, 0, 0, 0);
    }

    // Glowing cyan border + deep cobalt/slate background
    let is_border = dist > -2.5;

    // Lightning bolt polygon in center
    let nx = (x - 32.0) / 20.0;
    let ny = (y - 32.0) / 20.0;
    let in_upper_bolt = ny >= -0.75 && ny <= 0.10 && nx >= -0.45 - ny * 0.4 && nx <= 0.15 - ny * 0.55;
    let in_lower_bolt = ny >= -0.10 && ny <= 0.75 && nx >= -0.15 - ny * 0.55 && nx <= 0.45 - ny * 0.4;
    let in_bolt = in_upper_bolt || in_lower_bolt;

    let (r, g, b) = if in_bolt {
        (255u8, 215u8, 40u8) // High-voltage gold lightning bolt
    } else if is_border {
        (0u8, 210u8, 255u8) // Electric cyan border
    } else {
        let grad = ((y / 64.0) * 28.0) as u8;
        (14u8.saturating_add(grad / 2), 26u8.saturating_add(grad), 58u8.saturating_add(grad))
    };

    let alpha = if dist > 0.0 {
        ((1.0 - dist) * 255.0) as u8
    } else {
        255u8
    };
    (r, g, b, alpha)
}
