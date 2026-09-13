//! CyberV Phase 12: Temporal Drift & Hardware Trajectory Tests (HCE-5)
//!
//! Ref: Docs/rv10.md HCE-5:
//! StorageTrajectory, Monotonic Counters, NVMe Telemetry, Anomaly Detection,
//! Rollback / Snapshot Revert Detection, Virtual Nodes, Virtual Points.

use cyberv_agent::evidence::temporal::{
    MockStorageCollector, StorageTrajectory, TemporalAnomaly, TemporalAnomalyDetector,
    TemporalTrajectoryEngine,
};
use std::collections::BTreeMap;

#[test]
fn test_01_first_observation_insufficient_history() {
    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1500),
        power_cycles: Some(50),
        data_units_written_tb: Some(45),
        unsafe_shutdowns: Some(2),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, None);

    assert_eq!(eval.anomaly, TemporalAnomaly::InsufficientHistory);
    assert_eq!(eval.penalty, 0);
    assert_eq!(eval.consistency_score, 10000);
    assert!(!eval.commitment_hash.is_empty());
}

#[test]
fn test_02_normal_monotonic_progress() {
    let prev = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1500),
        power_cycles: Some(50),
        data_units_written_tb: Some(45),
        unsafe_shutdowns: Some(2),
        media_errors: Some(0),
        observed_at: 1757077200, // T0
    };

    // T1: 10 giờ sau đó ngoài đời thực (+36,000s)
    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1510),      // Tăng đúng 10 giờ
        power_cycles: Some(51),          // Khởi động lại 1 lần
        data_units_written_tb: Some(46), // Ghi thêm 1 TB
        unsafe_shutdowns: Some(2),
        media_errors: Some(0),
        observed_at: 1757077200 + 36000, // T1
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    assert_eq!(eval.anomaly, TemporalAnomaly::NormalProgress);
    assert_eq!(eval.penalty, 0);
    assert_eq!(eval.consistency_score, 10000);
}

#[test]
fn test_03_snapshot_rollback_power_on_hours_decrease() {
    // Kịch bản: Kẻ tấn công khôi phục lại VM Snapshot cách đây 3 tháng.
    // Giờ hoạt động hiện tại (50h) thấp hơn giờ hoạt động đã ghi nhận trước đó (4500h).
    let prev = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(4500),
        power_cycles: Some(120),
        data_units_written_tb: Some(80),
        unsafe_shutdowns: Some(1),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(50), // Giảm bất khả thi!
        power_cycles: Some(10),
        data_units_written_tb: Some(85),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 7200,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    match eval.anomaly {
        TemporalAnomaly::ImpossibleDecrease {
            field,
            old_val,
            new_val,
        } => {
            assert_eq!(field, "power_on_hours");
            assert_eq!(old_val, 4500);
            assert_eq!(new_val, 50);
        }
        _ => panic!("Phải phát hiện dị thường ImpossibleDecrease"),
    }

    assert!(
        eval.penalty >= 8000,
        "Phạt điểm nặng khi phát hiện Snapshot Rollback"
    );
    assert!(eval.consistency_score <= 2000);
}

#[test]
fn test_04_snapshot_rollback_data_written_decrease() {
    // Kịch bản: TBW bị giảm từ 100TB xuống 10TB
    let prev = StorageTrajectory {
        storage_id: "disk:wd-black-sn850x:11223344".to_string(),
        power_on_hours: Some(2000),
        power_cycles: Some(40),
        data_units_written_tb: Some(100),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let current = StorageTrajectory {
        storage_id: "disk:wd-black-sn850x:11223344".to_string(),
        power_on_hours: Some(2005),
        power_cycles: Some(41),
        data_units_written_tb: Some(10), // Giảm từ 100TB xuống 10TB!
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 18000,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    assert!(matches!(
        eval.anomaly,
        TemporalAnomaly::ImpossibleDecrease { .. }
    ));
    assert!(eval.penalty >= 7000);
}

#[test]
fn test_05_abnormal_jump_power_on_hours() {
    // Kịch bản: 1 giờ ngoài đời thực nhưng giờ hoạt động khai báo tăng vọt 500 giờ
    let prev = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1000),
        power_cycles: Some(20),
        data_units_written_tb: Some(30),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1500), // Nhảy vọt +500h trong khi chỉ trôi qua 1h
        power_cycles: Some(21),
        data_units_written_tb: Some(31),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600, // 1h sau
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    match eval.anomaly {
        TemporalAnomaly::AbnormalJump { field, delta } => {
            assert_eq!(field, "power_on_hours");
            assert_eq!(delta, 500);
        }
        _ => panic!("Phải phát hiện AbnormalJump"),
    }
}

#[test]
fn test_06_abnormal_jump_data_written() {
    // Kịch bản: 1 giờ ngoài đời thực nhưng TBW nhảy vọt 600TB (vượt quá giới hạn băng thông vật lý SSD)
    let prev = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1000),
        power_cycles: Some(20),
        data_units_written_tb: Some(30),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:s6z2nj0w123456".to_string(),
        power_on_hours: Some(1001),
        power_cycles: Some(20),
        data_units_written_tb: Some(630), // Ghi thêm 600TB trong 1h -> Bất khả thi vật lý!
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    assert!(matches!(eval.anomaly, TemporalAnomaly::AbnormalJump { .. }));
    assert!(eval.penalty > 0);
}

#[test]
fn test_07_device_replacement_valid() {
    // Kịch bản: Người dùng thay thế ổ SSD Samsung 980 Pro bằng Samsung 990 Pro mới
    let prev = StorageTrajectory {
        storage_id: "disk:samsung-980-pro:old123".to_string(),
        power_on_hours: Some(10000),
        power_cycles: Some(300),
        data_units_written_tb: Some(250),
        unsafe_shutdowns: Some(5),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let current = StorageTrajectory {
        storage_id: "disk:samsung-990-pro:new999".to_string(),
        power_on_hours: Some(5),
        power_cycles: Some(2),
        data_units_written_tb: Some(1),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 7200,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    assert_eq!(eval.anomaly, TemporalAnomaly::DeviceReplacement);
    assert_eq!(
        eval.penalty, 0,
        "Thay ổ đĩa mới không bị coi là dị thường thời gian"
    );
    assert_eq!(eval.consistency_score, 10000);
}

#[test]
fn test_08_missing_smart_data_returns_fail_safe() {
    // Kịch bản: Ổ đĩa USB hoặc không có quyền Admin nên không đọc được SMART
    let prev = StorageTrajectory::new("disk:generic:001", 1757077200);
    let current = StorageTrajectory::new("disk:generic:001", 1757077200 + 3600);

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));

    assert_eq!(eval.anomaly, TemporalAnomaly::MissingSmartData);
    assert_eq!(
        eval.penalty, 0,
        "Không có SMART không bị phạt điểm oan (Fail-safe)"
    );
    assert_eq!(eval.consistency_score, 10000);
}

#[test]
fn test_09_multi_disk_trajectory_evaluation() {
    let mut collector = MockStorageCollector::new();

    let disk1 = "disk:nvme1".to_string();
    let disk2 = "disk:nvme2".to_string();

    collector.insert_trajectory(StorageTrajectory {
        storage_id: disk1.clone(),
        power_on_hours: Some(1000),
        power_cycles: Some(30),
        data_units_written_tb: Some(50),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600,
    });

    collector.insert_trajectory(StorageTrajectory {
        storage_id: disk2.clone(),
        power_on_hours: Some(2000),
        power_cycles: Some(50),
        data_units_written_tb: Some(80),
        unsafe_shutdowns: Some(1),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600,
    });

    let mut prev_records = BTreeMap::new();
    prev_records.insert(
        disk1.clone(),
        StorageTrajectory {
            storage_id: disk1.clone(),
            power_on_hours: Some(999),
            power_cycles: Some(30),
            data_units_written_tb: Some(50),
            unsafe_shutdowns: Some(0),
            media_errors: Some(0),
            observed_at: 1757077200,
        },
    );
    prev_records.insert(
        disk2.clone(),
        StorageTrajectory {
            storage_id: disk2.clone(),
            power_on_hours: Some(1999),
            power_cycles: Some(50),
            data_units_written_tb: Some(80),
            unsafe_shutdowns: Some(1),
            media_errors: Some(0),
            observed_at: 1757077200,
        },
    );

    let engine = TemporalTrajectoryEngine::new(collector);
    let report = engine.evaluate_trajectories(&[disk1, disk2], &prev_records, 1757077200 + 3600);

    assert_eq!(report.evaluations.len(), 2);
    assert_eq!(report.overall_score, 10000);
    assert!(!report.has_anomalies);
}

#[test]
fn test_10_temporal_trajectory_virtual_nodes_generated() {
    let mut collector = MockStorageCollector::new();
    let disk_id = "disk:test".to_string();
    collector.insert_trajectory(StorageTrajectory {
        storage_id: disk_id.clone(),
        power_on_hours: Some(500),
        power_cycles: Some(10),
        data_units_written_tb: Some(12),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    });

    let engine = TemporalTrajectoryEngine::new(collector);
    let report = engine.evaluate_trajectories(&[disk_id], &BTreeMap::new(), 1757077200);

    assert!(!report.virtual_nodes.is_empty());
    let vnode = &report.virtual_nodes[0];
    assert_eq!(vnode.id, "vnode:storage_trajectory");
    assert_eq!(vnode.virtual_type, "STORAGE_TRAJECTORY");
    assert_eq!(vnode.derivation_version, 1);
    assert!(!vnode.virtual_hash.is_empty());
}

#[test]
fn test_11_temporal_trajectory_virtual_points_generated() {
    let mut collector = MockStorageCollector::new();
    let disk_id = "disk:test".to_string();
    collector.insert_trajectory(StorageTrajectory {
        storage_id: disk_id.clone(),
        power_on_hours: Some(500),
        power_cycles: Some(10),
        data_units_written_tb: Some(12),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    });

    let engine = TemporalTrajectoryEngine::new(collector);
    let report = engine.evaluate_trajectories(&[disk_id], &BTreeMap::new(), 1757077200);

    assert!(!report.virtual_points.is_empty());
    let point = &report.virtual_points[0];
    assert_eq!(point.id, "point:temporal_consistency");
    assert_eq!(point.value, 10000);
    assert_eq!(point.scale, 10000);
}

#[test]
fn test_12_deterministic_temporal_commitment_hash() {
    let t1 = StorageTrajectory {
        storage_id: "disk:samsung-990-pro".to_string(),
        power_on_hours: Some(100),
        power_cycles: Some(5),
        data_units_written_tb: Some(10),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let eval1 = TemporalAnomalyDetector::evaluate_drift(&t1, None);
    let eval2 = TemporalAnomalyDetector::evaluate_drift(&t1, None);

    assert_eq!(eval1.commitment_hash, eval2.commitment_hash);
    assert_eq!(eval1.commitment_hash.len(), 128); // SHA-512 hex
}

#[test]
fn test_13_tampered_history_detected() {
    let current = StorageTrajectory {
        storage_id: "disk:wd-sn850x".to_string(),
        power_on_hours: Some(100),
        power_cycles: Some(5),
        data_units_written_tb: Some(10),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600,
    };

    let legit_prev = StorageTrajectory {
        storage_id: "disk:wd-sn850x".to_string(),
        power_on_hours: Some(99),
        power_cycles: Some(5),
        data_units_written_tb: Some(10),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let tampered_prev = StorageTrajectory {
        storage_id: "disk:wd-sn850x".to_string(),
        power_on_hours: Some(999), // Bị kẻ gian sửa lịch sử
        power_cycles: Some(5),
        data_units_written_tb: Some(10),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    let eval_legit = TemporalAnomalyDetector::evaluate_drift(&current, Some(&legit_prev));
    let eval_tampered = TemporalAnomalyDetector::evaluate_drift(&current, Some(&tampered_prev));

    assert_ne!(eval_legit.commitment_hash, eval_tampered.commitment_hash);
    assert_eq!(eval_legit.consistency_score, 10000);
    assert!(eval_tampered.consistency_score <= 2000);
}

#[test]
fn test_14_combined_hours_and_tbw_anomaly() {
    let prev = StorageTrajectory {
        storage_id: "disk:nvme-attack".to_string(),
        power_on_hours: Some(2000),
        power_cycles: Some(100),
        data_units_written_tb: Some(80),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200,
    };

    // Vừa giảm giờ chạy vừa giảm TBW
    let current = StorageTrajectory {
        storage_id: "disk:nvme-attack".to_string(),
        power_on_hours: Some(100),
        power_cycles: Some(10),
        data_units_written_tb: Some(5),
        unsafe_shutdowns: Some(0),
        media_errors: Some(0),
        observed_at: 1757077200 + 3600,
    };

    let eval = TemporalAnomalyDetector::evaluate_drift(&current, Some(&prev));
    assert!(eval.penalty >= 7500);
}

#[test]
fn test_15_end_to_end_temporal_engine_integration() {
    let mut collector = MockStorageCollector::new();
    let disk_id = "disk:main-system-nvme".to_string();

    collector.insert_trajectory(StorageTrajectory {
        storage_id: disk_id.clone(),
        power_on_hours: Some(1250),
        power_cycles: Some(45),
        data_units_written_tb: Some(60),
        unsafe_shutdowns: Some(1),
        media_errors: Some(0),
        observed_at: 1757077200 + 7200,
    });

    let mut previous_db = BTreeMap::new();
    previous_db.insert(
        disk_id.clone(),
        StorageTrajectory {
            storage_id: disk_id.clone(),
            power_on_hours: Some(1248),
            power_cycles: Some(45),
            data_units_written_tb: Some(60),
            unsafe_shutdowns: Some(1),
            media_errors: Some(0),
            observed_at: 1757077200,
        },
    );

    let engine = TemporalTrajectoryEngine::new(collector);
    let report = engine.evaluate_trajectories(&[disk_id], &previous_db, 1757077200 + 7200);

    assert_eq!(report.overall_score, 10000);
    assert_eq!(report.virtual_points[0].value, 10000);
    assert_eq!(report.virtual_nodes[0].id, "vnode:storage_trajectory");
    assert!(!report.has_anomalies);
}
