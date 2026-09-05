import React, { useState } from 'react';
import { Shield, Mail, Lock, LogIn, X, Sparkles } from 'lucide-react';
import { supabase, isLiveConfigured } from '../services/supabase';
import type { UserSession } from '../types/device';

interface AuthModalProps {
  onClose: () => void;
  onSuccess: (session: UserSession) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ onClose, onSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDemoLogin = () => {
    const demoSession: UserSession = {
      user_id: 'u1-uuid-enterprise',
      email: 'security.officer@cyberv.internal',
      role: 'SecOps Enterprise Admin',
      is_demo: true,
    };
    onSuccess(demoSession);
    onClose();
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isLiveConfigured() || !supabase) {
      handleDemoLogin();
      return;
    }

    try {
      setLoading(true);
      setError(null);
      if (isSignUp) {
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        if (data.user) {
          onSuccess({
            user_id: data.user.id,
            email: data.user.email || email,
            role: 'User',
            is_demo: false,
          });
          onClose();
        }
      } else {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        if (data.user) {
          onSuccess({
            user_id: data.user.id,
            email: data.user.email || email,
            role: 'User',
            is_demo: false,
          });
          onClose();
        }
      }
    } catch (err: any) {
      setError(err.message || 'Lỗi xác thực');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuth = async (provider: 'google' | 'azure') => {
    if (!isLiveConfigured() || !supabase) {
      handleDemoLogin();
      return;
    }
    await supabase.auth.signInWithOAuth({ provider });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '440px' }}
      >
        {/* Header */}
        <div
          style={{
            padding: '24px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.08), rgba(99, 102, 241, 0.1))',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '10px',
                background: 'rgba(0, 240, 255, 0.2)',
                border: '1px solid var(--cyan-primary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield size={20} color="var(--cyan-primary)" />
            </div>
            <div>
              <h3 style={{ fontSize: '17px', fontWeight: 800, color: '#fff' }}>
                {isSignUp ? 'Đăng Ký Tài Khoản' : 'Đăng Nhập An Ninh'}
              </h3>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                CyberV Identity Authentication
              </div>
            </div>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm" style={{ padding: '4px' }}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Quick 1-Click Demo Login Banner */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(0, 240, 255, 0.08)',
              border: '1px solid rgba(0, 240, 255, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--cyan-primary)' }}>
                Chế độ Trải nghiệm Nhanh
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Đăng nhập tức thì với tài khoản SecOps Admin mẫu.
              </div>
            </div>
            <button onClick={handleDemoLogin} className="btn btn-primary btn-sm" style={{ flexShrink: 0 }}>
              <Sparkles size={12} />
              <span>1-Click Login</span>
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Email
              </label>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <Mail size={16} color="var(--text-muted)" />
                <input
                  type="email"
                  placeholder="admin@enterprise.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
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
            </div>

            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Mật Khẩu
              </label>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <Lock size={16} color="var(--text-muted)" />
                <input
                  type="password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
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
            </div>

            {error && (
              <div style={{ fontSize: '12px', color: 'var(--crimson-danger)' }}>{error}</div>
            )}

            <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '6px' }}>
              <LogIn size={15} />
              <span>{loading ? 'Đang Xử Lý...' : isSignUp ? 'Tạo Tài Khoản' : 'Đăng Nhập'}</span>
            </button>
          </form>

          {/* Social OAuth Buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ textAlign: 'center', fontSize: '11px', color: 'var(--text-dim)' }}>
              HOẶC ĐĂNG NHẬP DOANH NGHIỆP
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button
                type="button"
                onClick={() => handleOAuth('google')}
                className="btn btn-secondary btn-sm"
              >
                Google
              </button>
              <button
                type="button"
                onClick={() => handleOAuth('azure')}
                className="btn btn-secondary btn-sm"
              >
                Microsoft
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '14px 24px',
            borderTop: '1px solid var(--border-subtle)',
            textAlign: 'center',
            fontSize: '12px',
            color: 'var(--text-muted)',
            background: 'rgba(0,0,0,0.1)',
          }}
        >
          {isSignUp ? 'Đã có tài khoản? ' : 'Chưa có tài khoản? '}
          <button
            type="button"
            onClick={() => setIsSignUp(!isSignUp)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--cyan-primary)',
              fontWeight: 700,
              cursor: 'pointer',
              padding: 0,
            }}
          >
            {isSignUp ? 'Đăng nhập ngay' : 'Đăng ký'}
          </button>
        </div>
      </div>
    </div>
  );
};
