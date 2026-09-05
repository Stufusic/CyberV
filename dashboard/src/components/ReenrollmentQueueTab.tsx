import React, { useState } from 'react';
import {
  GitPullRequest,
  CheckCircle2,
  XCircle,
  ArrowRight,
} from 'lucide-react';
import type { ReenrollmentRequest } from '../types/device';
import { apiService } from '../services/api';

interface ReenrollmentQueueTabProps {
  requests: ReenrollmentRequest[];
  onActionComplete: () => void;
}

export const ReenrollmentQueueTab: React.FC<ReenrollmentQueueTabProps> = ({
  requests,
  onActionComplete,
}) => {
  const [filterStatus, setFilterStatus] = useState<'PENDING' | 'APPROVED' | 'REJECTED' | 'ALL'>('PENDING');
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const handleApprove = async (reqId: string) => {
    try {
      setProcessingId(reqId);
      const res = await apiService.approveReenrollment(reqId);
      setToastMessage(res.message);
      onActionComplete();
      setTimeout(() => setToastMessage(null), 4000);
    } catch (err: any) {
      alert('Lỗi phê duyệt: ' + err.message);
    } finally {
      setProcessingId(null);
    }
  };

  const handleReject = async (reqId: string) => {
    if (!confirm('Bạn có chắc chắn muốn TỪ CHỐI yêu cầu Tái cấp quyền phần cứng này?')) return;
    try {
      setProcessingId(reqId);
      const res = await apiService.rejectReenrollment(reqId);
      setToastMessage(res.message);
      onActionComplete();
      setTimeout(() => setToastMessage(null), 4000);
    } catch (err: any) {
      alert('Lỗi từ chối: ' + err.message);
    } finally {
      setProcessingId(null);
    }
  };

  const filteredRequests = requests.filter((r) => {
    if (filterStatus === 'ALL') return true;
    return r.status === filterStatus;
  });

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
            Hàng Chờ Xét Duyệt Tái Cấp Quyền (Dynamic Re-enrollment Pipeline)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Xem xét biến động linh kiện, tính toán điểm rủi ro (Risk Score 0-10000) và phê duyệt thăng cấp đồ thị.
          </p>
        </div>

        {/* Filter Buttons */}
        <div
          style={{
            display: 'flex',
            background: 'var(--bg-surface-elevated)',
            borderRadius: 'var(--radius-md)',
            padding: '2px',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {(['PENDING', 'APPROVED', 'REJECTED', 'ALL'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className="btn btn-sm btn-ghost"
              style={{
                background: filterStatus === st ? 'var(--bg-surface-hover)' : 'transparent',
                color: filterStatus === st ? '#fff' : 'var(--text-muted)',
                fontWeight: filterStatus === st ? 700 : 500,
                borderRadius: 'var(--radius-sm)',
              }}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Notification Toast */}
      {toastMessage && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid var(--emerald-success)',
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            animation: 'modal-appear 0.2s ease',
          }}
        >
          <CheckCircle2 size={18} color="var(--emerald-success)" />
          <span style={{ fontSize: '14px', fontWeight: 600 }}>{toastMessage}</span>
        </div>
      )}

      {/* Requests List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        {filteredRequests.map((req) => {
          const isPending = req.status === 'PENDING';
          const isProcessing = processingId === req.id;
          const riskPercent = (req.risk_score / 100).toFixed(2);

          return (
            <div
              key={req.id}
              className="glass-card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '18px',
                border: isPending
                  ? '1px solid rgba(245, 158, 11, 0.4)'
                  : '1px solid var(--border-subtle)',
                background: isPending ? 'rgba(245, 158, 11, 0.02)' : 'var(--bg-glass)',
              }}
            >
              {/* Request Header */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  borderBottom: '1px solid var(--border-subtle)',
                  paddingBottom: '14px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <GitPullRequest
                    size={20}
                    color={
                      req.status === 'APPROVED'
                        ? 'var(--emerald-success)'
                        : req.status === 'REJECTED'
                        ? 'var(--crimson-danger)'
                        : 'var(--amber-warning)'
                    }
                  />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="font-mono" style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                        Device: {req.device_id}
                      </span>
                      <span className={`badge badge-${req.status.toLowerCase()}`}>
                        {req.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      Mã yêu cầu: {req.id} • Thời gian: {new Date(req.created_at).toLocaleString()}
                    </div>
                  </div>
                </div>

                {/* Risk Score Pill */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      ĐIỂM RỦI RO (RISK SCORE)
                    </div>
                    <div style={{ fontSize: '16px', fontWeight: 800, color: req.risk_score > 3000 ? 'var(--crimson-danger)' : 'var(--amber-warning)' }}>
                      {riskPercent}% ({req.risk_score}/10000)
                    </div>
                  </div>
                  <span className={`badge badge-risk-${req.risk_level.toLowerCase()}`}>
                    {req.risk_level}
                  </span>
                </div>
              </div>

              {/* Version & State Hash Comparison (GraphDiff Box) */}
              <div
                style={{
                  background: 'rgba(0,0,0,0.3)',
                  borderRadius: 'var(--radius-md)',
                  padding: '14px 16px',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                  gap: '16px',
                }}
              >
                {/* Previous State */}
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    TRẠNG THÁI HIỆN TẠI (PREVIOUS)
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
                    Graph Version v{req.new_graph_version - 1}
                  </div>
                  <div className="font-mono text-dim" style={{ fontSize: '10px', wordBreak: 'break-all' }}>
                    State: {req.previous_state_hash}
                  </div>
                </div>

                {/* Arrow */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <div
                    style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '50%',
                      background: 'rgba(0, 240, 255, 0.1)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <ArrowRight size={16} color="var(--cyan-primary)" />
                  </div>
                </div>

                {/* Target State */}
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    TRẠNG THÁI ĐỀ XUẤT (PROMOTED TARGET)
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--cyan-primary)', marginBottom: '4px' }}>
                    Graph Version v{req.new_graph_version} (Monotonic Increase)
                  </div>
                  <div className="font-mono text-cyan" style={{ fontSize: '10px', wordBreak: 'break-all' }}>
                    State: {req.new_state_hash}
                  </div>
                </div>
              </div>

              {/* Mutation Details & Decision Matrix Rationale */}
              <div>
                <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  LÝ DO & MA TRẬN QUYẾT ĐỊNH (DECISION MATRIX):
                </div>
                <div style={{ fontSize: '13px', color: '#fff', marginBottom: '8px' }}>
                  {req.reason}
                </div>

                {/* Changed components bullets */}
                {req.modified_components && req.modified_components.length > 0 && (
                  <div
                    style={{
                      padding: '10px 14px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'rgba(245, 158, 11, 0.08)',
                      border: '1px solid rgba(245, 158, 11, 0.2)',
                    }}
                  >
                    <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--amber-warning)', marginBottom: '4px' }}>
                      CHI TIẾT LINH KIỆN BIẾN ĐỘNG (GRAPhDIFF):
                    </div>
                    <ul style={{ paddingLeft: '18px', fontSize: '12px', color: 'var(--text-primary)' }}>
                      {req.modified_components.map((c, i) => (
                        <li key={i} style={{ marginBottom: '2px' }}>
                          {c}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Action Buttons (Only for PENDING) */}
              {isPending && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                    gap: '12px',
                    borderTop: '1px solid var(--border-subtle)',
                    paddingTop: '14px',
                  }}
                >
                  <button
                    onClick={() => handleReject(req.id)}
                    className="btn btn-secondary btn-sm"
                    disabled={isProcessing}
                    style={{ color: 'var(--crimson-danger)' }}
                  >
                    <XCircle size={14} />
                    <span>Từ Chối & Khóa</span>
                  </button>

                  <button
                    onClick={() => handleApprove(req.id)}
                    className="btn btn-success btn-sm"
                    disabled={isProcessing}
                  >
                    <CheckCircle2 size={14} />
                    <span>{isProcessing ? 'Đang Xử Lý...' : 'Phê Duyệt & Thăng Cấp (Approve)'}</span>
                  </button>
                </div>
              )}
            </div>
          );
        })}

        {filteredRequests.length === 0 && (
          <div className="glass-card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
            <CheckCircle2 size={36} color="var(--emerald-success)" style={{ margin: '0 auto 12px', opacity: 0.7 }} />
            <div style={{ fontSize: '16px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
              Hàng đợi trống
            </div>
            <div style={{ fontSize: '13px' }}>Không có yêu cầu Tái cấp quyền nào ở trạng thái {filterStatus}.</div>
          </div>
        )}
      </div>
    </div>
  );
};
