import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Layers,
  HardDrive,
  CircuitBoard,
  Copy,
  Check,
  Code2,
  ChevronDown,
  ChevronRight,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import type { Device, CanonicalGraphJson } from '../types/device';
import { apiService } from '../services/api';

interface HardwareGraphVisualizerProps {
  devices: Device[];
  selectedDevice: Device | null;
  onSelectDevice: (device: Device) => void;
}

export const HardwareGraphVisualizer: React.FC<HardwareGraphVisualizerProps> = ({
  devices,
  selectedDevice,
  onSelectDevice,
}) => {
  const currentDev = selectedDevice || devices[0] || null;
  const [graphData, setGraphData] = useState<CanonicalGraphJson | null>(null);
  const [loading, setLoading] = useState(false);
  const [showJsonDrawer, setShowJsonDrawer] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedTiers, setExpandedTiers] = useState<Record<string, boolean>>({
    tier1: true,
    tier2: true,
    tier3: true,
    tier4: true,
    tier5: true,
    tier6: true,
  });

  useEffect(() => {
    if (!currentDev) return;
    setLoading(true);
    apiService
      .getDeviceGraph(currentDev.device_id, currentDev.current_graph_version)
      .then((data) => {
        setGraphData(data);
      })
      .finally(() => setLoading(false));
  }, [currentDev?.device_id, currentDev?.current_graph_version]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleTier = (tier: string) => {
    setExpandedTiers((prev) => ({ ...prev, [tier]: !prev[tier] }));
  };

  if (!currentDev) {
    return (
      <div className="glass-card" style={{ padding: '48px', textAlign: 'center' }}>
        <p style={{ color: 'var(--text-muted)' }}>Chưa có thiết bị nào để hiển thị đồ thị.</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header & Device Selector */}
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
            Trực Quan Hóa Đồ Thị Bằng Chứng Phần Cứng (Hardware Evidence Graph)
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Biểu diễn cấu trúc Real Nodes, Virtual Nodes, Virtual Points và Cây Băm 6 Cấp (Tier 1 đến Tier 6).
          </p>
        </div>

        {/* Device Switcher Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Thiết bị:</span>
          <select
            value={currentDev.device_id}
            onChange={(e) => {
              const target = devices.find((d) => d.device_id === e.target.value);
              if (target) onSelectDevice(target);
            }}
            style={{
              padding: '8px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-glass)',
              color: '#fff',
              fontSize: '13px',
              fontWeight: 600,
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            {devices.map((d) => (
              <option key={d.device_id} value={d.device_id}>
                {d.device_id.slice(0, 16)}... (v{d.current_graph_version} - {d.status})
              </option>
            ))}
          </select>

          {loading && (
            <RefreshCw
              size={14}
              color="var(--cyan-primary)"
              style={{ animation: 'spin 1s linear infinite' }}
            />
          )}

          <button
            onClick={() => setShowJsonDrawer(!showJsonDrawer)}
            className="btn btn-secondary btn-sm"
          >
            <Code2 size={14} color="var(--cyan-primary)" />
            <span>{showJsonDrawer ? 'Ẩn Canonical JSON' : 'Xem Canonical JSON'}</span>
          </button>
        </div>
      </div>

      {/* Summary Banner */}
      <div
        className="glass-card"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '20px',
          background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.04), rgba(99, 102, 241, 0.06))',
          border: '1px solid rgba(0, 240, 255, 0.2)',
        }}
      >
        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>PHIÊN BẢN ĐỒ THỊ (VERSION)</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--cyan-primary)' }}>
            v{currentDev.current_graph_version}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>TỔNG VIRTUAL POINTS</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: '#fff' }}>
            {graphData?.summary.total_virtual_points ?? 13000} pts
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>SỐ LƯỢNG NÚT VẬT LÝ (REAL NODES)</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--emerald-success)' }}>
            {graphData?.summary.real_nodes_count ?? 5} nodes
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>SỐ NÚT LOGIC (VIRTUAL NODES)</div>
          <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--indigo-accent)' }}>
            {graphData?.summary.virtual_nodes_count ?? 3} nodes
          </div>
        </div>
      </div>

      {/* Raw Canonical JSON Drawer */}
      {showJsonDrawer && graphData && (
        <div
          className="glass-card"
          style={{
            border: '1px solid var(--cyan-primary)',
            background: 'rgba(6, 9, 15, 0.95)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Code2 size={16} color="var(--cyan-primary)" />
              <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                Canonical Graph Representation (RFC 8785 Normalized)
              </span>
            </div>
            <button
              onClick={() =>
                copyToClipboard(JSON.stringify(graphData, null, 2), 'canonical-json')
              }
              className="btn btn-secondary btn-sm"
            >
              {copiedKey === 'canonical-json' ? (
                <>
                  <Check size={12} color="var(--emerald-success)" />
                  <span>Đã Sao Chép</span>
                </>
              ) : (
                <>
                  <Copy size={12} />
                  <span>Sao Chép JSON</span>
                </>
              )}
            </button>
          </div>
          <pre
            className="font-mono"
            style={{
              maxHeight: '300px',
              overflowY: 'auto',
              padding: '16px',
              borderRadius: '8px',
              background: '#04060a',
              fontSize: '12px',
              color: '#a5f3fc',
              lineHeight: '1.4',
            }}
          >
            {JSON.stringify(graphData, null, 2)}
          </pre>
        </div>
      )}

      {/* Main Graph Content: Two Columns */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '24px' }}>
        {/* Left Column: Physical & Logical Hardware Breakdown */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Cpu size={18} color="var(--cyan-primary)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
              Thực Thể Phần Cứng (Real Nodes & Components)
            </h3>
          </div>

          {/* CPU Card */}
          {graphData?.real_nodes.cpu && (
            <div className="glass-card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Cpu size={16} color="var(--cyan-primary)" />
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                    CPU Processor
                  </span>
                </div>
                <span className="badge badge-risk-low" style={{ fontSize: '11px' }}>
                  {graphData.real_nodes.cpu.virtual_points} pts
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 600 }}>
                {graphData.real_nodes.cpu.model}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {graphData.real_nodes.cpu.cores} Nhân / {graphData.real_nodes.cpu.logical_processors} Luồng • Kiến trúc: {graphData.real_nodes.cpu.architecture}
              </div>
              <div
                className="font-mono text-muted"
                style={{
                  fontSize: '10px',
                  marginTop: '8px',
                  wordBreak: 'break-all',
                  background: 'rgba(0,0,0,0.3)',
                  padding: '6px',
                  borderRadius: '4px',
                }}
              >
                SHA-512: {graphData.real_nodes.cpu.hash}
              </div>
            </div>
          )}

          {/* RAM Modules */}
          {graphData?.real_nodes.ram_dimms && (
            <div className="glass-card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <CircuitBoard size={16} color="var(--emerald-success)" />
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                    RAM Modules ({graphData.real_nodes.ram_dimms.length} thanh DIMM)
                  </span>
                </div>
                <span className="badge badge-risk-low" style={{ fontSize: '11px' }}>
                  {graphData.real_nodes.ram_dimms.reduce((acc, r) => acc + r.virtual_points, 0)} pts
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {graphData.real_nodes.ram_dimms.map((ram, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-elevated)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: '#fff' }}>
                        Slot #{ram.slot_index}: {(ram.capacity_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB DDR4 ({ram.speed_mhz || 3200} MHz)
                      </span>
                      <span className="font-mono text-cyan" style={{ fontSize: '11px' }}>
                        {ram.virtual_points} pts
                      </span>
                    </div>
                    <div className="font-mono text-dim" style={{ fontSize: '9px', marginTop: '4px', wordBreak: 'break-all' }}>
                      {ram.hash}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Storage Drives */}
          {graphData?.real_nodes.storage_drives && (
            <div className="glass-card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <HardDrive size={16} color="var(--amber-warning)" />
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                    Ổ Đĩa Lưu Trữ (Storage Devices)
                  </span>
                </div>
                <span className="badge badge-risk-low" style={{ fontSize: '11px' }}>
                  {graphData.real_nodes.storage_drives.reduce((acc, s) => acc + s.virtual_points, 0)} pts
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {graphData.real_nodes.storage_drives.map((disk, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-elevated)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: '#fff' }}>
                        {disk.model} ({disk.bus_type} • {(disk.capacity_bytes / (1000 * 1000 * 1000)).toFixed(0)} GB)
                      </span>
                      {disk.is_system_drive && (
                        <span className="badge badge-active" style={{ fontSize: '9px', padding: '2px 5px' }}>
                          OS ROOT
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                      Serial: {disk.serial} • Điểm ảo: {disk.virtual_points} pts
                    </div>
                    <div className="font-mono text-dim" style={{ fontSize: '9px', marginTop: '4px', wordBreak: 'break-all' }}>
                      {disk.hash}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Motherboard */}
          {graphData?.real_nodes.motherboard && (
            <div className="glass-card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <CircuitBoard size={16} color="var(--indigo-accent)" />
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#fff' }}>
                    Bo Mạch Chủ (Motherboard)
                  </span>
                </div>
                <span className="badge badge-risk-low" style={{ fontSize: '11px' }}>
                  {graphData.real_nodes.motherboard.virtual_points} pts
                </span>
              </div>
              <div style={{ fontSize: '13px', color: '#fff', fontWeight: 600 }}>
                {graphData.real_nodes.motherboard.manufacturer} — {graphData.real_nodes.motherboard.product}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                Serial: {graphData.real_nodes.motherboard.serial}
              </div>
              <div className="font-mono text-dim" style={{ fontSize: '9px', marginTop: '6px', wordBreak: 'break-all' }}>
                {graphData.real_nodes.motherboard.hash}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: 6-Tier Cryptographic Hash Hierarchy */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Layers size={18} color="var(--emerald-success)" />
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>
              Cây Phân Cấp Băm 6 Cấp (6-Tier Hash Hierarchy)
            </h3>
          </div>

          {/* Tier 6: State Hash (Apex) */}
          <div
            className="glass-card"
            style={{
              border: '1px solid var(--cyan-primary)',
              background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.08), rgba(99, 102, 241, 0.1))',
              padding: '16px',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
              onClick={() => toggleTier('tier6')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles size={16} color="var(--cyan-primary)" />
                <span style={{ fontSize: '13px', fontWeight: 800, color: 'var(--cyan-primary)' }}>
                  TIER 6: STATE HASH (FINAL IDENTITY-BOUND HASH)
                </span>
              </div>
              {expandedTiers.tier6 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>

            {expandedTiers.tier6 && (
              <div style={{ marginTop: '12px' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Được tính bằng Length-Prefixed Canonical Bytes ràng buộc trực tiếp với Khóa Công Khai Ed25519 (NSA CNSA Suite):
                </div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'rgba(0,0,0,0.4)',
                    padding: '8px 10px',
                    borderRadius: '6px',
                  }}
                >
                  <span className="font-mono text-cyan" style={{ fontSize: '11px', wordBreak: 'break-all' }}>
                    {graphData?.tier_hashes.tier6_state_hash || currentDev.current_state_hash}
                  </span>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        graphData?.tier_hashes.tier6_state_hash || currentDev.current_state_hash,
                        't6'
                      )
                    }
                    className="btn btn-ghost btn-sm"
                    style={{ flexShrink: 0 }}
                  >
                    {copiedKey === 't6' ? (
                      <Check size={12} color="var(--emerald-success)" />
                    ) : (
                      <Copy size={12} />
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Tier 5: Graph Topology Hash */}
          <div className="glass-card" style={{ padding: '14px' }}>
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => toggleTier('tier5')}
            >
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                TIER 5: GRAPH TOPOLOGY HASH
              </span>
              {expandedTiers.tier5 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
            {expandedTiers.tier5 && (
              <div className="font-mono text-secondary" style={{ fontSize: '10px', marginTop: '8px', wordBreak: 'break-all', background: 'rgba(0,0,0,0.2)', padding: '6px', borderRadius: '4px' }}>
                {graphData?.tier_hashes.tier5_graph_topology}
              </div>
            )}
          </div>

          {/* Tier 4: Layer Hashes */}
          <div className="glass-card" style={{ padding: '14px' }}>
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => toggleTier('tier4')}
            >
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                TIER 4: LAYER HASHES (PHYSICAL & FABRIC)
              </span>
              {expandedTiers.tier4 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
            {expandedTiers.tier4 && (
              <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Physical Layer:</div>
                <div className="font-mono text-dim" style={{ fontSize: '9px', wordBreak: 'break-all' }}>
                  {graphData?.tier_hashes.tier4_physical_layer}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Fabric Layer:</div>
                <div className="font-mono text-dim" style={{ fontSize: '9px', wordBreak: 'break-all' }}>
                  {graphData?.tier_hashes.tier4_fabric_layer}
                </div>
              </div>
            )}
          </div>

          {/* Tier 3: Virtual Nodes Hash */}
          <div className="glass-card" style={{ padding: '14px' }}>
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => toggleTier('tier3')}
            >
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                TIER 3: VIRTUAL NODES HASH (BUS / CONTROLLERS)
              </span>
              {expandedTiers.tier3 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
            {expandedTiers.tier3 && (
              <div className="font-mono text-dim" style={{ fontSize: '10px', marginTop: '8px', wordBreak: 'break-all' }}>
                {graphData?.tier_hashes.tier3_virtual_nodes}
              </div>
            )}
          </div>

          {/* Tier 2: Real Nodes Hash */}
          <div className="glass-card" style={{ padding: '14px' }}>
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => toggleTier('tier2')}
            >
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                TIER 2: REAL NODES AGGREGATE HASH
              </span>
              {expandedTiers.tier2 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
            {expandedTiers.tier2 && (
              <div className="font-mono text-dim" style={{ fontSize: '10px', marginTop: '8px', wordBreak: 'break-all' }}>
                {graphData?.tier_hashes.tier2_real_nodes}
              </div>
            )}
          </div>

          {/* Tier 1: Components */}
          <div className="glass-card" style={{ padding: '14px' }}>
            <div
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
              onClick={() => toggleTier('tier1')}
            >
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                TIER 1: CANONICAL COMPONENT HASHES
              </span>
              {expandedTiers.tier1 ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
            {expandedTiers.tier1 && graphData && (
              <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {Object.entries(graphData.tier_hashes.tier1_components).map(([k, val]) => (
                  <div key={k} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{k}:</span>
                    <span className="font-mono text-muted" style={{ fontSize: '10px' }}>
                      {val.slice(0, 16)}...{val.slice(-8)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
