import React from 'react';
import {
  LayoutDashboard,
  Laptop,
  Share2,
  Clock,
  GitPullRequest,
  CheckCircle2,
} from 'lucide-react';

export type TabType = 'overview' | 'devices' | 'graph' | 'reenroll' | 'events';

interface SidebarProps {
  currentTab: TabType;
  onSelectTab: (tab: TabType) => void;
  pendingCount: number;
  totalDevices: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  pendingCount,
  totalDevices,
}) => {
  const navItems = [
    {
      id: 'overview' as TabType,
      label: 'Tổng Quan',
      sublabel: 'Overview & KPIs',
      icon: LayoutDashboard,
    },
    {
      id: 'devices' as TabType,
      label: 'Thiết Bị',
      sublabel: 'Device Fleet',
      icon: Laptop,
      badge: totalDevices > 0 ? String(totalDevices) : undefined,
    },
    {
      id: 'graph' as TabType,
      label: 'Đồ Thị Phần Cứng',
      sublabel: 'Evidence Graph & Hashes',
      icon: Share2,
    },
    {
      id: 'reenroll' as TabType,
      label: 'Hàng Chờ Duyệt',
      sublabel: 'Re-enrollment Queue',
      icon: GitPullRequest,
      badge: pendingCount > 0 ? String(pendingCount) : undefined,
      badgeColor: 'var(--amber-warning)',
    },
    {
      id: 'events' as TabType,
      label: 'Nhật Ký An Ninh',
      sublabel: 'Audit Log Stream',
      icon: Clock,
    },
  ];

  return (
    <aside className="app-sidebar">
      {/* Navigation Links */}
      <div style={{ padding: '24px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        <div
          style={{
            fontSize: '11px',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            color: 'var(--text-dim)',
            fontWeight: 700,
            padding: '0 12px 6px',
          }}
        >
          Security Console
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 14px',
                borderRadius: 'var(--radius-md)',
                background: isActive
                  ? 'linear-gradient(90deg, rgba(0, 240, 255, 0.12), rgba(99, 102, 241, 0.05))'
                  : 'transparent',
                border: isActive ? '1px solid rgba(0, 240, 255, 0.25)' : '1px solid transparent',
                color: isActive ? 'var(--cyan-primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all var(--transition-fast)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Icon
                  size={18}
                  color={isActive ? 'var(--cyan-primary)' : 'var(--text-secondary)'}
                />
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: isActive ? '#fff' : 'inherit' }}>
                    {item.label}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{item.sublabel}</div>
                </div>
              </div>

              {item.badge && (
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-full)',
                    background: item.badgeColor
                      ? `rgba(245, 158, 11, 0.15)`
                      : 'rgba(255, 255, 255, 0.1)',
                    color: item.badgeColor || 'var(--text-primary)',
                    border: item.badgeColor
                      ? `1px solid rgba(245, 158, 11, 0.3)`
                      : '1px solid rgba(255, 255, 255, 0.15)',
                  }}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Security Status Box at Bottom */}
      <div style={{ marginTop: 'auto', padding: '20px 16px' }}>
        <div
          style={{
            padding: '14px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(19, 28, 46, 0.6)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <CheckCircle2 size={16} color="var(--emerald-success)" />
            <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--emerald-success)' }}>
              Protocol Active
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
            Zero-Trust Device Binding với Ed25519 & SHA-512. Không lưu khóa riêng tư.
          </div>
        </div>
      </div>
    </aside>
  );
};
