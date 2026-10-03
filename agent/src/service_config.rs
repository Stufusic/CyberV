//! CyberV Service Configuration (P1-2 — wire AgentDaemon thật vào service)
//!
//! Ref: Docs/PHASE1_2_IMPLEMENTATION_PLAN.md P1-2:
//! "service.rs: khởi tạo HttpDeviceTransport (từ config %ProgramData%\CyberV\agent_config.json)
//!  + WindowsWmiCollector; chạy AgentDaemon::tick() theo attestation_interval_secs."
//!
//! Nguyên tắc fail-closed: không có config / config sai định dạng → service
//! chạy ở chế độ keep-alive IPC và báo trạng thái NOT WIRED — tuyệt đối không
//! đoán URL/key hay chạy daemon với giá trị mặc định.

use serde::Deserialize;

pub const SERVICE_CONFIG_ENV: &str = "CYBERV_AGENT_CONFIG";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AgentServiceConfig {
    /// Endpoint server (Supabase). Bắt buộc HTTPS — HttpDeviceTransport sẽ
    /// từ chối http:// (localhost miễn trừ cho kiểm thử).
    pub server_url: String,
    /// Supabase anon key (public-facing, không phải secret service-role).
    pub anon_key: String,
    /// JWT của user sở hữu thiết bị (cấp qua dashboard; service không tự login).
    pub user_jwt: String,
    /// Chu kỳ attestation (giây). Mặc định 300, clamp tối thiểu 30.
    #[serde(default = "default_attestation_interval")]
    pub attestation_interval_secs: u64,
    #[serde(default = "default_offline_grace")]
    pub max_offline_grace_secs: u64,
}

fn default_attestation_interval() -> u64 {
    300
}

fn default_offline_grace() -> u64 {
    86400
}

impl AgentServiceConfig {
    const MIN_ATTESTATION_INTERVAL: u64 = 30;
    const MIN_OFFLINE_GRACE: u64 = 600;

    /// Validate + clamp: URL phải https (loopback miễn trừ), các trường không rỗng,
    /// khoảng thời gian trong biên độ hợp lý.
    pub fn validated(mut self) -> Result<Self, String> {
        if self.server_url.trim().is_empty()
            || self.anon_key.trim().is_empty()
            || self.user_jwt.trim().is_empty()
        {
            return Err("server_url / anon_key / user_jwt không được rỗng".to_string());
        }
        let lower = self.server_url.to_ascii_lowercase();
        let host = lower
            .strip_prefix("https://")
            .or_else(|| lower.strip_prefix("http://"))
            .unwrap_or(&lower);
        let is_loopback =
            host.starts_with("localhost") || host.starts_with("127.0.0.1") || host.starts_with("[::1]");
        if !lower.starts_with("https://") && !is_loopback {
            return Err("server_url phải dùng HTTPS (loopback miễn trừ cho kiểm thử)".to_string());
        }
        if self.attestation_interval_secs < Self::MIN_ATTESTATION_INTERVAL {
            self.attestation_interval_secs = Self::MIN_ATTESTATION_INTERVAL;
        }
        if self.max_offline_grace_secs < Self::MIN_OFFLINE_GRACE {
            self.max_offline_grace_secs = Self::MIN_OFFLINE_GRACE;
        }
        Ok(self)
    }

    /// Đường dẫn config mặc định: %ProgramData%\CyberV\agent_config.json
    /// (có thể override bằng env CYBERV_AGENT_CONFIG — phục vụ kiểm thử/triển khai đặc biệt).
    pub fn default_config_path() -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var(SERVICE_CONFIG_ENV) {
            return Some(std::path::PathBuf::from(p));
        }
        std::env::var("ProgramData")
            .ok()
            .map(|pd| std::path::PathBuf::from(pd).join("CyberV").join("agent_config.json"))
    }

    /// Nạp config từ đường dẫn mặc định. Trả về:
    /// - `Ok(Some(config))`: đọc + validate thành công
    /// - `Ok(None)`: file không tồn tại (chưa được cấp phát — chế độ keep-alive)
    /// - `Err(msg)`: file tồn tại nhưng hỏng/sai — lỗi cấu hình cần cảnh báo
    pub fn load_from_default_path() -> Result<Option<Self>, String> {
        let path = match Self::default_config_path() {
            Some(p) => p,
            None => return Ok(None), // không có ProgramData (môi trường lạ) → coi như chưa cấu hình
        };
        Self::load_from_path(&path)
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Option<Self>, String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("Không đọc được {}: {}", path.display(), e)),
        };
        let cfg: Self = serde_json::from_str(&content)
            .map_err(|e| format!("Config {} sai định dạng JSON/schema: {}", path.display(), e))?;
        Ok(Some(cfg.validated()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cyberv_cfg_test_{}_{:x}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("agent_config.json");
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn parses_valid_config_and_clamps_intervals() {
        let p = write_tmp(
            "valid",
            r#"{"server_url":"https://xyz.supabase.co","anon_key":"anon","user_jwt":"jwt","attestation_interval_secs":5}"#,
        );
        let cfg = AgentServiceConfig::load_from_path(&p)
            .unwrap()
            .expect("config phải được nạp");
        // clamp 5 -> 30 (MIN_ATTESTATION_INTERVAL)
        assert_eq!(cfg.attestation_interval_secs, 30);
        assert_eq!(cfg.max_offline_grace_secs, 86400);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn missing_file_means_not_configured_not_error() {
        let p = std::env::temp_dir().join("cyberv_cfg_test_khong_ton_tai.json");
        let _ = std::fs::remove_file(&p);
        assert!(AgentServiceConfig::load_from_path(&p).unwrap().is_none());
    }

    #[test]
    fn rejects_insecure_url() {
        let p = write_tmp(
            "insecure",
            r#"{"server_url":"http://evil.example.com","anon_key":"a","user_jwt":"b"}"#,
        );
        assert!(AgentServiceConfig::load_from_path(&p).is_err());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn rejects_empty_fields() {
        let p = write_tmp(
            "empty",
            r#"{"server_url":"https://x.supabase.co","anon_key":"","user_jwt":"b"}"#,
        );
        assert!(AgentServiceConfig::load_from_path(&p).is_err());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn malformed_json_is_error_not_none() {
        let p = write_tmp("bad", r#"{not json"#);
        assert!(AgentServiceConfig::load_from_path(&p).is_err());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn allows_loopback_http_for_testing() {
        let p = write_tmp(
            "loopback",
            r#"{"server_url":"http://127.0.0.1:8080","anon_key":"a","user_jwt":"b"}"#,
        );
        assert!(AgentServiceConfig::load_from_path(&p).unwrap().is_some());
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }
}
