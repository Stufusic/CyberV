import React from 'react';
import {
  Laptop,
  CheckCircle2,
  AlertTriangle,
  ShieldX,
  ShieldCheck,
  Cpu,
  Layers,
  Activity,
  ArrowUpRight,
} from 'lucide-react';
import type { Device, ReenrollmentRequest, DeviceEvent } from '../types/device';
import type { TabType } from './Sidebar';

interface OverviewTabProps {
  devices: Device[];
  requests: ReenrollmentRequest[];
  events: DeviceEvent[];
  onNavigate: (tab: TabType) => void;
  onSelectDeviceForGraph: (device: Device) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  devices,
  requests,
  events,
  onNavigate,
  onSelectDeviceForGraph,
}) => {
  const activeCount = devices.filter((d) => d.status === 'ACTIVE').length;
  const pendingCount = requests.filter((r) => r.status === 'PENDING').length;
  const revokedCount = devices.filter((d) => d.status === 'REVOKED').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Title & Description */}
      <div>
        <h1 style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginBottom: '6px' }}>
          Trung Tâm Giám Sát & Điều Hành An Ninh Thiết Bị
        </h1>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
          Hệ thống xác thực thiết bị vật lý đa lớp dựa trên Bằng chứng Phần cứng, Cây Băm SHA-512 và Khóa số Ed25519.
        </p>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid-kpi">
        {/* Total Devices */}
        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(0, 240, 255, 0.1)',
              border: '1px solid rgba(0, 240, 255, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Laptop size={24} color="var(--cyan-primary)" />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
              TỔNG THIẾT BỊ
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: '#fff' }}>{devices.length}</div>
          </div>
        </div>

        {/* Active Devices */}
        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <CheckCircle2 size={24} color="var(--emerald-success)" />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
              ĐANG HOẠT ĐỘNG
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--emerald-success)' }}>
              {activeCount}
            </div>
          </div>
        </div>

        {/* Pending Re-enrollment */}
        <div
          className="glass-card"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
            border: pendingCount > 0 ? '1px solid var(--amber-warning)' : '1px solid var(--border-subtle)',
            background: pendingCount > 0 ? 'rgba(245, 158, 11, 0.05)' : 'var(--bg-glass)',
          }}
        >
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <AlertTriangle size={24} color="var(--amber-warning)" />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
              CHỜ PHÊ DUYỆT ĐỔI PHẦN CỨNG
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--amber-warning)' }}>
              {pendingCount}
            </div>
          </div>
        </div>

        {/* Revoked Devices */}
        <div className="glass-card" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <ShieldX size={24} color="var(--crimson-danger)" />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
              ĐÃ THU HỒI / VÔ HIỆU HÓA
            </div>
            <div style={{ fontSize: '26px', fontWeight: 800, color: 'var(--crimson-danger)' }}>
              {revokedCount}
            </div>
          </div>
        </div>
      </div>

      {/* Security Invariant Banner */}
      <div
        className="glass-card"
        style={{
          background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.06), rgba(99, 102, 241, 0.08))',
          borderColor: 'rgba(0, 240, 255, 0.25)',
          padding: '24px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' }}>
          <ShieldCheck size={20} color="var(--cyan-primary)" />
          <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
            Nguyên Tắc An Ninh Bất Biến (Security Invariants — Rule.md)
          </h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          <div style={{ padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.2)' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--cyan-primary)', marginBottom: '4px' }}>
              Identity ≠ Device
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Tài khoản người dùng (User ID) hoàn toàn tách biệt với mã thiết bị ngẫu nhiên CSPRNG (Device ID).
            </div>
          </div>
          <div style={{ padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.2)' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--emerald-success)', marginBottom: '4px' }}>
              Hardware Hash ≠ Private Key
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Thông tin phần cứng chỉ là Bằng chứng Trạng thái (Evidence), khóa Ed25519 được sinh từ nguồn Entropy hệ điều hành.
            </div>
          </div>
          <div style={{ padding: '12px', borderRadius: '8px', background: 'rgba(0,0,0,0.2)' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--amber-warning)', marginBottom: '4px' }}>
              Final Hash ≠ Credential
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Mã băm State Hash không thể dùng làm mật khẩu. Mọi quyền truy cập phải có chữ ký số trên Thử thách Nonce 60s.
            </div>
          </div>
        </div>
      </div>

      {/* Two Column Section: Fleet Preview & Recent Events */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '24px' }}>
        {/* Left: Device Fleet Preview */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={18} color="var(--cyan-primary)" />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>Hạ Tầng Thiết Bị Gần Đây</h3>
            </div>
            <button onClick={() => onNavigate('devices')} className="btn btn-ghost btn-sm" style={{ gap: '4px' }}>
              <span>Xem Tất Cả</span>
              <ArrowUpRight size={14} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {devices.slice(0, 3).map((dev) => (
              <div
                key={dev.device_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 14px',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="font-mono" style={{ fontSize: '13px', fontWeight: 600, color: '#fff' }}>
                      {dev.device_id.slice(0, 18)}...
                    </span>
                    <span
                      className={`badge badge-${dev.status.toLowerCase()}`}
                      style={{ fontSize: '10px', padding: '2px 6px' }}
                    >
                      {dev.status}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Phiên bản Đồ thị: v{dev.current_graph_version} • Rủi ro: {dev.risk_level}
                  </div>
                </div>

                <button
                  onClick={() => {
                    onSelectDeviceForGraph(dev);
                    onNavigate('graph');
                  }}
                  className="btn btn-secondary btn-sm"
                  style={{ fontSize: '11px', padding: '4px 8px' }}
                >
                  <Layers size={12} />
                  <span>Xem Đồ Thị</span>
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Realtime Event Stream Preview */}
        <div className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={18} color="var(--emerald-success)" />
              <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff' }}>Nhật Ký An Ninh Mới Nhất</h3>
            </div>
            <button onClick={() => onNavigate('events')} className="btn btn-ghost btn-sm" style={{ gap: '4px' }}>
              <span>Dòng Thời Gian</span>
              <ArrowUpRight size={14} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {events.slice(0, 4).map((ev) => (
              <div
                key={ev.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(19, 28, 46, 0.4)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        color:
                          ev.event_type.includes('APPROVED') || ev.event_type.includes('VERIFIED')
                            ? 'var(--emerald-success)'
                            : ev.event_type.includes('REVOKED') || ev.event_type.includes('REJECTED')
                            ? 'var(--crimson-danger)'
                            : 'var(--cyan-primary)',
                      }}
                    >
                      {ev.event_type}
                    </span>
                    <span className="font-mono text-muted" style={{ fontSize: '11px' }}>
                      {ev.device_id.slice(0, 8)}...
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                    {new Date(ev.created_at).toLocaleTimeString()} — {new Date(ev.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
