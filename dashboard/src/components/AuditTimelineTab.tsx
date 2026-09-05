import React, { useState } from 'react';
import {
  Clock,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Code2,
  Filter,
} from 'lucide-react';
import type { DeviceEvent } from '../types/device';

interface AuditTimelineTabProps {
  events: DeviceEvent[];
}

export const AuditTimelineTab: React.FC<AuditTimelineTabProps> = ({ events }) => {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const eventTypes = [
    'ALL',
    'ATTESTATION_VERIFIED',
    'REENROLL_REQUESTED',
    'REENROLL_USER_APPROVED',
    'REENROLL_USER_REJECTED',
    'DEVICE_REVOKED',
    'CHALLENGE_ISSUED',
    'DEVICE_ENROLLED',
  ];

  const filteredEvents = events.filter((ev) => {
    if (filterType === 'ALL') return true;
    return ev.event_type === filterType;
  });

  const getEventBadge = (type: string) => {
    if (type.includes('APPROVED') || type.includes('VERIFIED')) {
      return { color: 'var(--emerald-success)', bg: 'rgba(16, 185, 129, 0.15)', icon: CheckCircle2 };
    }
    if (type.includes('REVOKED') || type.includes('REJECTED')) {
      return { color: 'var(--crimson-danger)', bg: 'rgba(239, 68, 68, 0.15)', icon: ShieldAlert };
    }
    if (type.includes('REENROLL')) {
      return { color: 'var(--amber-warning)', bg: 'rgba(245, 158, 11, 0.15)', icon: AlertTriangle };
    }
    return { color: 'var(--cyan-primary)', bg: 'rgba(0, 240, 255, 0.15)', icon: Clock };
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
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
            Nhật Ký Kiểm Toán An Ninh (Security Audit Timeline)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Chuỗi bản ghi bất biến (Append-Only Audit Log) ghi lại mọi thao tác chứng thực, cấp quyền và thu hồi thiết bị.
          </p>
        </div>

        {/* Filter Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Filter size={14} color="var(--text-muted)" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            style={{
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-subtle)',
              color: '#fff',
              fontSize: '13px',
              fontWeight: 600,
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            {eventTypes.map((t) => (
              <option key={t} value={t}>
                {t === 'ALL' ? 'Tất Cả Sự Kiện' : t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Timeline Stream */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {filteredEvents.map((ev) => {
          const badge = getEventBadge(ev.event_type);
          const Icon = badge.icon;
          const isExpanded = expandedEvents[ev.id];

          return (
            <div
              key={ev.id}
              className="glass-card"
              style={{
                padding: '16px 20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              {/* Row Main Info */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                }}
                onClick={() => toggleExpand(ev.id)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <div
                    style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: '10px',
                      background: badge.bg,
                      border: `1px solid ${badge.color}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <Icon size={18} color={badge.color} />
                  </div>

                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 800, color: badge.color }}>
                        {ev.event_type}
                      </span>
                      <span className="font-mono text-muted" style={{ fontSize: '12px' }}>
                        Device: {ev.device_id.slice(0, 18)}...
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      Event ID: {ev.id} • Phiên bản: v{ev.event_version}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: '#fff' }}>
                      {new Date(ev.created_at).toLocaleTimeString()}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {new Date(ev.created_at).toLocaleDateString()}
                    </div>
                  </div>

                  <button className="btn btn-ghost btn-sm" style={{ padding: '4px' }}>
                    {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </button>
                </div>
              </div>

              {/* Metadata Details Box */}
              {isExpanded && (
                <div
                  style={{
                    background: 'rgba(0,0,0,0.4)',
                    borderRadius: '8px',
                    padding: '12px 16px',
                    border: '1px solid var(--border-subtle)',
                    animation: 'modal-appear 0.2s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    <Code2 size={12} color="var(--cyan-primary)" />
                    <span>EVENT METADATA (JSON PAYLOAD):</span>
                  </div>
                  <pre
                    className="font-mono"
                    style={{
                      fontSize: '11px',
                      color: '#a5f3fc',
                      background: '#04060a',
                      padding: '10px',
                      borderRadius: '6px',
                      overflowX: 'auto',
                    }}
                  >
                    {JSON.stringify(ev.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}

        {filteredEvents.length === 0 && (
          <div className="glass-card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
            <Clock size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
            <div style={{ fontSize: '16px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
              Không có sự kiện kiểm toán
            </div>
            <div style={{ fontSize: '13px' }}>Chưa có bản ghi nào khớp với bộ lọc {filterType}.</div>
          </div>
        )}
      </div>
    </div>
  );
};
