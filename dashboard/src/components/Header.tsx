import React from 'react';
import { Shield, RefreshCw, Cpu, Database, User, LogIn, LogOut } from 'lucide-react';
import { apiService } from '../services/api';
import type { UserSession } from '../types/device';

interface HeaderProps {
  user: UserSession | null;
  isDemo: boolean;
  onRefresh: () => void;
  onOpenAuth: () => void;
  onLogout: () => void;
  isLoading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  user,
  isDemo,
  onRefresh,
  onOpenAuth,
  onLogout,
  isLoading,
}) => {
  const toggleMode = () => {
    apiService.setDemoMode(!isDemo);
  };

  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '16px 36px',
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(12, 18, 30, 0.85)',
        backdropFilter: 'blur(16px)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div
          style={{
            width: '42px',
            height: '42px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(99, 102, 241, 0.3))',
            border: '1px solid var(--cyan-primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(0, 240, 255, 0.3)',
          }}
        >
          <Shield size={24} color="#00f0ff" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '18px', fontWeight: 800, letterSpacing: '0.05em', color: '#fff' }}>
              CYBER<span style={{ color: 'var(--cyan-primary)' }}>V</span>
            </span>
            <span
              style={{
                fontSize: '10px',
                padding: '2px 6px',
                borderRadius: '4px',
                background: 'rgba(0, 240, 255, 0.1)',
                color: 'var(--cyan-primary)',
                border: '1px solid rgba(0, 240, 255, 0.3)',
                fontWeight: 700,
              }}
            >
              CNSA / FIPS 180-4
            </span>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Enterprise Device-Binding Security Protocol
          </div>
        </div>
      </div>

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Mode Switcher Pill */}
        <button
          onClick={toggleMode}
          className="btn btn-secondary btn-sm"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 12px',
            border: isDemo ? '1px solid var(--amber-warning)' : '1px solid var(--emerald-success)',
            background: isDemo ? 'rgba(245, 158, 11, 0.08)' : 'rgba(16, 185, 129, 0.08)',
          }}
          title="Click to toggle between Demo and Live Supabase mode"
        >
          {isDemo ? (
            <>
              <Cpu size={14} color="var(--amber-warning)" />
              <span style={{ color: 'var(--amber-warning)', fontSize: '12px' }}>Interactive Demo Mode</span>
            </>
          ) : (
            <>
              <Database size={14} color="var(--emerald-success)" />
              <span style={{ color: 'var(--emerald-success)', fontSize: '12px' }}>Live Supabase Mode</span>
            </>
          )}
        </button>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          className="btn btn-secondary btn-sm"
          disabled={isLoading}
          style={{ padding: '6px 10px' }}
          title="Refresh Data"
        >
          <RefreshCw
            size={14}
            style={{
              animation: isLoading ? 'spin 1s linear infinite' : 'none',
              transformOrigin: 'center',
            }}
          />
        </button>

        {/* User Account / Auth */}
        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '4px 10px',
                borderRadius: '8px',
                background: 'var(--bg-surface-elevated)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div
                style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: 'var(--indigo-accent)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <User size={14} color="#fff" />
              </div>
              <span style={{ fontSize: '13px', fontWeight: 600 }}>{user.email}</span>
            </div>
            <button
              onClick={onLogout}
              className="btn btn-ghost btn-sm"
              title="Sign Out"
              style={{ padding: '6px 8px' }}
            >
              <LogOut size={16} />
            </button>
          </div>
        ) : (
          <button onClick={onOpenAuth} className="btn btn-primary btn-sm">
            <LogIn size={14} />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
};
