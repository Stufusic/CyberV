// ============================================================================
// CyberV - Stufusic
// Copyright (c) 2024-2026 Tersun - Stufusic. All rights reserved.
//
// PROPRIETARY & SOURCE CODE LICENSE NOTICE
// This software is protected by international copyright laws and treaties.
// Unauthorized reproduction, reverse engineering, or distribution of this code,
// or any portion of it, is strictly prohibited without explicit written consent.
//
// DISCLAIMER OF LIABILITY (MIỄN TRỪ TRÁCH NHIỆM):
// THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
// OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN IT.
// ============================================================================
//! build.rs của agent — biên dịch WinRT shim (M-3 WiFi Direct / M-4 BLE).
//!
//! Ref: Docs/HYBRID_DISTRIBUTION_PLAN.md §1.1: shim build qua `cc` crate ở
//! build.rs — KHÔNG thêm CMake/MSBuild project; `cc` đã có sẵn trong
//! Cargo.lock (transitive) nên không thêm crate mới (cấm danh sách #6).
//!
//! Chiến lược trung thực: môi trường có Windows SDK + projection cppwinrt →
//! biên dịch shim WinRT thật; nếu không → shim STUB (mọi hàm trả
//! E_UNSUPPORTED) để crate vẫn build được khắp nơi — runtime báo "không hỗ
//! trợ" rõ ràng, không bao giờ giả vờ thấy peer.

use std::path::{Path, PathBuf};

fn main() {
    let is_windows = std::env::var("CARGO_CFG_WINDOWS").is_ok();
    if !is_windows {
        // Không phải Windows — shim stub (Rust side cũng cfg-gate, không link).
        compile_stub();
        return;
    }

    match locate_windows_sdk() {
        Some((sdk_dir, sdk_ver)) => {
            compile_winrt_shim(&sdk_dir, &sdk_ver);
            // windowsapp.lib — umbrella lib WinRT của SDK.
            let lib_dir = sdk_dir.join("Lib").join(&sdk_ver).join("um").join("x64");
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=dylib=windowsapp");
        }
        None => {
            // Không có SDK → shim stub (không WinRT — chỉ std C++).
            println!("cargo:warning=CyberV shim: Windows SDK không tìm thấy — biên dịch shim STUB (WFD/BLE báo không hỗ trợ lúc runtime)");
            compile_stub();
        }
    }
}

/// Tìm Windows SDK + phiên bản mới nhất có projection cppwinrt.
fn locate_windows_sdk() -> Option<(PathBuf, String)> {
    // 1. Env do VS prompt đặt (nếu cargo chạy trong đó).
    if let (Ok(dir), Ok(ver)) = (
        std::env::var("WindowsSdkDir"),
        std::env::var("WindowsSDKVersion"),
    ) {
        let ver = ver.trim_end_matches('\\').to_string();
        if !dir.is_empty() && !ver.is_empty() && Path::new(&dir).join("Include").join(&ver).join("cppwinrt").is_dir() {
            return Some((PathBuf::from(dir), ver));
        }
    }
    // 2. Quét đường dẫn chuẩn.
    let root = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10");
    let include_dir = root.join("Include");
    let mut versions: Vec<String> = std::fs::read_dir(&include_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .filter(|v| v.starts_with("10."))
        .collect();
    versions.sort();
    for ver in versions.into_iter().rev() {
        if include_dir.join(&ver).join("cppwinrt").is_dir() {
            return Some((root, ver));
        }
    }
    None
}

fn include_dirs(sdk_dir: &Path, sdk_ver: &str) -> Vec<PathBuf> {
    let base = sdk_dir.join("Include").join(sdk_ver);
    vec![
        base.join("cppwinrt"),
        base.join("um"),
        base.join("shared"),
        base.join("ucrt"),
    ]
}

fn compile_winrt_shim(sdk_dir: &Path, sdk_ver: &str) {
    // SDK chỉ pre-generate một số namespace phổ biến (BLE có, WiFiDirect
    // KHÔNG) — chạy cppwinrt.exe sinh đủ projection vào OUT_DIR (cache theo
    // file marker; chỉ chạy lại khi thiếu).
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR do cargo cấp"));
    let gen_dir = out_dir.join("cppwinrt-gen");
    let marker = gen_dir
        .join("winrt")
        .join("Windows.Devices.WiFiDirect.h");
    if !marker.is_file() {
        let tool = sdk_dir
            .join("bin")
            .join(sdk_ver)
            .join("x64")
            .join("cppwinrt.exe");
        if !tool.is_file() {
            eprintln!("cyberv shim: không thấy cppwinrt.exe tại {}", tool.display());
            compile_stub();
            return;
        }
        std::fs::create_dir_all(&gen_dir).expect("tạo dir projection");
        let status = std::process::Command::new(&tool)
            .args(["-in", "local", "-out"])
            .arg(&gen_dir)
            .status()
            .expect("chạy cppwinrt.exe");
        if !status.success() || !marker.is_file() {
            eprintln!("cyberv shim: cppwinrt.exe thất bại — fallback shim STUB");
            compile_stub();
            return;
        }
    }

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("shim/cyberv_shim_winrt.cpp")
        .flag("/std:c++20")
        .flag("/EHsc")
        .flag("/Zc:__cplusplus")
        .flag("/permissive-")
        .flag("/DWIN32_LEAN_AND_MEAN")
        .flag("/DNOMINMAX")
        .warnings(false);
    // Projection SINH RA đứng trước SDK pre-gen để toàn vẹn namespace.
    build.include(&gen_dir);
    for dir in include_dirs(sdk_dir, sdk_ver) {
        build.include(dir);
    }
    build.compile("cyberv_shim_winrt");
    println!("cargo:rerun-if-changed=shim/cyberv_shim_winrt.cpp");
    println!("cargo:rerun-if-changed=shim/cyberv_shim.h");
    println!("cargo:rerun-if-changed=build.rs");
}

fn compile_stub() {
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("shim/cyberv_shim_stub.cpp")
        .flag("/std:c++17")
        .flag("/EHsc")
        .warnings(false);
    build.compile("cyberv_shim_stub");
    println!("cargo:rerun-if-changed=shim/cyberv_shim_stub.cpp");
    println!("cargo:rerun-if-changed=build.rs");
}
