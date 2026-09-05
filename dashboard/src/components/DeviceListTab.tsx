import React, { useState } from 'react';
import {
  Search,
  Copy,
  Check,
  Layers,
  ShieldX,
  Clock,
  Key,
  Hash,
  Activity,
} from 'lucide-react';
import type { Device, DeviceStatus } from '../types/device';

interface DeviceListTabProps {
  devices: Device[];
  onSelectDeviceForGraph: (device: Device) => void;
  onOpenRevokeModal: (device: Device) => void;
}

export const DeviceListTab: React.FC<DeviceListTabProps> = ({
  devices,
  onSelectDeviceForGraph,
  onOpenRevokeModal,
}) => {
  const [filterStatus, setFilterStatus] = useState<DeviceStatus | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredDevices = devices.filter((dev) => {
    if (filterStatus !== 'ALL' && dev.status !== filterStatus) return false;
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      return (
        dev.device_id.toLowerCase().includes(q) ||
        dev.public_key.toLowerCase().includes(q) ||
        dev.current_state_hash.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header & Controls */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '16px',
        }}
      >
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#fff', marginBottom: '4px' }}>
            Danh Sách Thiết Bị Định Danh (Device Fleet)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Quản lý vòng đời, tình trạng an ninh và các cấp độ băm trạng thái của từng thiết bị.
          </p>
        </div>

        {/* Search and Filters */}
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '12px' }}>
          {/* Search Box */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 12px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-subtle)',
              width: '240px',
            }}
          >
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Tìm theo Device ID / Key..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#fff',
                fontSize: '13px',
                outline: 'none',
                width: '100%',
              }}
            />
          </div>

          {/* Status Filter Buttons */}
          <div
            style={{
              display: 'flex',
              background: 'var(--bg-surface-elevated)',
              borderRadius: 'var(--radius-md)',
              padding: '2px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {(['ALL', 'ACTIVE', 'PENDING', 'REVOKED'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setFilterStatus(status)}
                className="btn btn-sm btn-ghost"
                style={{
                  background: filterStatus === status ? 'var(--bg-surface-hover)' : 'transparent',
                  color: filterStatus === status ? '#fff' : 'var(--text-muted)',
                  fontWeight: filterStatus === status ? 700 : 500,
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Devices Grid */}
      <div className="grid-cards">
        {filteredDevices.map((dev) => {
          const isRevoked = dev.status === 'REVOKED';
          return (
            <div
              key={dev.device_id}
              className="glass-card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '16px',
                border: isRevoked
                  ? '1px solid rgba(239, 68, 68, 0.4)'
                  : dev.status === 'PENDING'
                  ? '1px solid rgba(245, 158, 11, 0.4)'
                  : '1px solid var(--border-subtle)',
                background: isRevoked ? 'rgba(239, 68, 68, 0.03)' : 'var(--bg-glass)',
              }}
            >
              {/* Card Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div className={`pulse-dot pulse-dot-${dev.status.toLowerCase()}`} />
                  <span
                    className={`badge badge-${dev.status.toLowerCase()}`}
                    style={{ fontSize: '11px' }}
                  >
                    {dev.status}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span
                    style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-full)',
                      background: 'rgba(0, 240, 255, 0.1)',
                      color: 'var(--cyan-primary)',
                      border: '1px solid rgba(0, 240, 255, 0.25)',
                    }}
                  >
                    Graph v{dev.current_graph_version}
                  </span>
                  <span
                    className={`badge badge-risk-${dev.risk_level.toLowerCase()}`}
                    style={{ fontSize: '11px' }}
                  >
                    Risk: {dev.risk_level}
                  </span>
                </div>
              </div>

              {/* Device ID */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' }}>
                  DEVICE IDENTITY (UUID v4)
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="font-mono" style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>
                    {dev.device_id}
                  </span>
                  <button
                    onClick={() => copyToClipboard(dev.device_id, `id-${dev.device_id}`)}
                    className="btn btn-ghost btn-sm"
                    style={{ padding: '2px 6px' }}
                    title="Copy Device ID"
                  >
                    {copiedKey === `id-${dev.device_id}` ? (
                      <Check size={12} color="var(--emerald-success)" />
                    ) : (
                      <Copy size={12} />
                    )}
                  </button>
                </div>
              </div>

              {/* Cryptographic Hashes Snippets */}
              <div
                style={{
                  background: 'rgba(0,0,0,0.25)',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                {/* Ed25519 Public Key */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: 'var(--text-muted)' }}>
                    <Key size={10} color="var(--indigo-accent)" />
                    <span>ED25519 PUBLIC KEY</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '2px' }}>
                    <span className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                      {dev.public_key.slice(0, 20)}...{dev.public_key.slice(-8)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(dev.public_key, `pk-${dev.device_id}`)}
                      className="btn btn-ghost btn-sm"
                      style={{ padding: '2px 4px' }}
                    >
                      {copiedKey === `pk-${dev.device_id}` ? (
                        <Check size={10} color="var(--emerald-success)" />
                      ) : (
                        <Copy size={10} />
                      )}
                    </button>
                  </div>
                </div>

                {/* Tier 6 State Hash */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: 'var(--text-muted)' }}>
                    <Hash size={10} color="var(--cyan-primary)" />
                    <span>TIER 6 STATE HASH (SHA-512)</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '2px' }}>
                    <span className="font-mono text-secondary" style={{ fontSize: '11px' }}>
                      {dev.current_state_hash.slice(0, 20)}...{dev.current_state_hash.slice(-8)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(dev.current_state_hash, `sh-${dev.device_id}`)}
                      className="btn btn-ghost btn-sm"
                      style={{ padding: '2px 4px' }}
                    >
                      {copiedKey === `sh-${dev.device_id}` ? (
                        <Check size={10} color="var(--emerald-success)" />
                      ) : (
                        <Copy size={10} />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Last Seen At */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-dim)' }}>
                <Clock size={12} />
                <span>Hoạt động lần cuối: {new Date(dev.last_seen_at).toLocaleString()}</span>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: 'auto', paddingTop: '10px' }}>
                <button
                  onClick={() => onSelectDeviceForGraph(dev)}
                  className="btn btn-secondary btn-sm"
                  style={{ flex: 1 }}
                >
                  <Layers size={13} color="var(--cyan-primary)" />
                  <span>Xem Đồ Thị</span>
                </button>

                {!isRevoked && (
                  <button
                    onClick={() => onOpenRevokeModal(dev)}
                    className="btn btn-danger btn-sm"
                    title="Thu hồi quyền truy cập thiết bị này ngay lập tức"
                  >
                    <ShieldX size={13} />
                    <span>Thu Hồi</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {filteredDevices.length === 0 && (
        <div
          className="glass-card"
          style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}
        >
          <Activity size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
          <div style={{ fontSize: '16px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
            Không tìm thấy thiết bị nào
          </div>
          <div style={{ fontSize: '13px' }}>Hãy thử điều chỉnh bộ lọc hoặc từ khóa tìm kiếm.</div>
        </div>
      )}
    </div>
  );
};
