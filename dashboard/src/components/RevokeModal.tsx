import React, { useState } from 'react';
import { ShieldAlert, AlertOctagon, X } from 'lucide-react';
import type { Device } from '../types/device';
import { apiService } from '../services/api';

interface RevokeModalProps {
  device: Device | null;
  onClose: () => void;
  onSuccess: () => void;
}

export const RevokeModal: React.FC<RevokeModalProps> = ({
  device,
  onClose,
  onSuccess,
}) => {
  if (!device) return null;

  const [confirmInput, setConfirmInput] = useState('');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isConfirmed = confirmInput.trim() === device.device_id;

  const handleRevoke = async () => {
    if (!isConfirmed) return;
    try {
      setLoading(true);
      setError(null);
      await apiService.revokeDevice(device.device_id, reason || 'User initiated revocation');
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Lỗi khi thu hồi thiết bị');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ border: '1px solid rgba(239, 68, 68, 0.5)' }}
      >
        {/* Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(239, 68, 68, 0.08)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertOctagon size={22} color="var(--crimson-danger)" />
            <h3 style={{ fontSize: '16px', fontWeight: 800, color: '#fff' }}>
              Xác Nhận Thu Hồi Quyền Thiết Bị (Device Revocation)
            </h3>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm" style={{ padding: '4px' }}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Danger Warning Box */}
          <div
            style={{
              padding: '14px 16px',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex',
              gap: '12px',
            }}
          >
            <ShieldAlert size={20} color="var(--crimson-danger)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '13px', color: '#ffb3b3', lineHeight: '1.4' }}>
              <strong>CẢNH BÁO AN NINH CẤP CAO:</strong> Hành động này sẽ khóa vĩnh viễn khóa công khai Ed25519 của thiết bị. Mọi phiên chứng thực Nonce và yêu cầu xác thực sau đó sẽ bị từ chối với mã 403 Forbidden.
            </div>
          </div>

          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
              MÃ THIẾT BỊ SẮP BỊ THU HỒI:
            </div>
            <div
              className="font-mono"
              style={{
                fontSize: '13px',
                fontWeight: 700,
                color: 'var(--cyan-primary)',
                background: 'rgba(0,0,0,0.3)',
                padding: '8px 12px',
                borderRadius: '6px',
                userSelect: 'all',
              }}
            >
              {device.device_id}
            </div>
          </div>

          {/* Reason Input */}
          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
              Lý do thu hồi (Tùy chọn):
            </label>
            <input
              type="text"
              placeholder="VD: Thiết bị bị thất lạc, nghi ngờ phần cứng bị can thiệp..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-surface-elevated)',
                border: '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '13px',
                outline: 'none',
              }}
            />
          </div>

          {/* Confirmation Input */}
          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
              Nhập chính xác mã thiết bị phía trên để mở khóa nút xác nhận:
            </label>
            <input
              type="text"
              placeholder={device.device_id}
              value={confirmInput}
              onChange={(e) => setConfirmInput(e.target.value)}
              className="font-mono"
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-surface-elevated)',
                border: isConfirmed ? '1px solid var(--emerald-success)' : '1px solid var(--border-subtle)',
                color: '#fff',
                fontSize: '12px',
                outline: 'none',
              }}
            />
          </div>

          {error && (
            <div style={{ fontSize: '12px', color: 'var(--crimson-danger)' }}>
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '16px 24px',
            borderTop: '1px solid var(--border-subtle)',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '12px',
            background: 'rgba(0,0,0,0.1)',
          }}
        >
          <button onClick={onClose} className="btn btn-secondary btn-sm" disabled={loading}>
            Hủy Bỏ
          </button>
          <button
            onClick={handleRevoke}
            className="btn btn-danger btn-sm"
            disabled={!isConfirmed || loading}
          >
            {loading ? 'Đang Thu Hồi...' : 'Xác Nhận Thu Hồi Vĩnh Viễn'}
          </button>
        </div>
      </div>
    </div>
  );
};
