// ====================================================================
// CyberV Device-Binding Security Protocol: Frontend Types
// Synchronized with PostgreSQL Schema, RLS, and Rust Protocol Models
// ====================================================================

export type DeviceStatus = 'ACTIVE' | 'PENDING' | 'REVOKED' | 'REJECTED';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'TRUSTED' | 'AUTO_PROMOTE' | 'REQUIRES_USER_APPROVAL' | 'REJECTED';

export interface Device {
  id: string;
  user_id: string;
  device_id: string;
  public_key: string;
  current_graph_hash: string;
  current_state_hash: string;
  current_graph_version: number;
  status: DeviceStatus;
  risk_level: RiskLevel;
  created_at: string;
  updated_at: string;
  last_seen_at: string;
}

export interface CanonicalGraphJson {
  version: number;
  device_id: string;
  real_nodes: {
    cpu?: {
      hash: string;
      model: string;
      cores: number;
      logical_processors: number;
      architecture: string;
      vendor_id?: string;
      virtual_points: number;
    };
    ram_dimms?: Array<{
      hash: string;
      capacity_bytes: number;
      speed_mhz?: number;
      part_number?: string;
      slot_index: number;
      virtual_points: number;
    }>;
    storage_drives?: Array<{
      hash: string;
      model: string;
      serial: string;
      capacity_bytes: number;
      bus_type: string;
      is_system_drive: boolean;
      virtual_points: number;
    }>;
    motherboard?: {
      hash: string;
      manufacturer: string;
      product: string;
      serial: string;
      virtual_points: number;
    };
  };
  virtual_nodes: {
    system_fabric?: {
      hash: string;
      bus_type: string;
      virtual_points: number;
    };
    memory_controller?: {
      hash: string;
      channels: number;
      total_capacity_bytes: number;
      virtual_points: number;
    };
    storage_controller?: {
      hash: string;
      total_drives: number;
      virtual_points: number;
    };
  };
  tier_hashes: {
    tier1_components: Record<string, string>;
    tier2_real_nodes: string;
    tier3_virtual_nodes: string;
    tier4_physical_layer: string;
    tier4_fabric_layer: string;
    tier5_graph_topology: string;
    tier6_state_hash: string;
  };
  summary: {
    total_virtual_points: number;
    real_nodes_count: number;
    virtual_nodes_count: number;
  };
}

export interface DeviceGraph {
  id: string;
  device_id: string;
  graph_version: number;
  graph_hash: string;
  canonical_graph_json: CanonicalGraphJson;
  created_at: string;
}

export interface ReenrollmentRequest {
  id: string;
  device_id: string;
  user_id: string;
  previous_state_hash: string;
  new_state_hash: string;
  new_graph_hash: string;
  new_graph_version: number;
  new_graph_json: CanonicalGraphJson;
  risk_score: number; // Điểm nguyên 0 - 10000 (0.00% - 100.00%)
  risk_level: RiskLevel;
  decision: DecisionType;
  reason: string;
  proof_signature: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  created_at: string;
  reviewed_at?: string;
  modified_components?: string[];
}

export interface DeviceEvent {
  id: string;
  device_id: string;
  event_type: string;
  event_version: number;
  metadata: Record<string, any>;
  created_at: string;
}

export interface UserSession {
  user_id: string;
  email: string;
  role: string;
  is_demo: boolean;
}
