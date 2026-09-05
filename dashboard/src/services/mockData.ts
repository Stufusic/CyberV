// ====================================================================
// CyberV Device-Binding Security Protocol: Mock & Demo Fixtures
// Realistic Cryptographic Hashes (SHA-512) and Hardware Graph States
// ====================================================================

import type { Device, CanonicalGraphJson, ReenrollmentRequest, DeviceEvent } from '../types/device';

export const MOCK_GRAPH_BASELINE: CanonicalGraphJson = {
  version: 1,
  device_id: '550e8400-e29b-41d4-a716-446655440001',
  real_nodes: {
    cpu: {
      hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
      model: 'Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz',
      cores: 8,
      logical_processors: 16,
      architecture: 'x86_64',
      vendor_id: 'GenuineIntel',
      virtual_points: 3500,
    },
    ram_dimms: [
      {
        hash: 'b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01',
        capacity_bytes: 8589934592, // 8GB
        speed_mhz: 3200,
        part_number: 'KHX3200C16D4/8GX',
        slot_index: 0,
        virtual_points: 750,
      },
      {
        hash: 'c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef02',
        capacity_bytes: 8589934592, // 8GB
        speed_mhz: 3200,
        part_number: 'KHX3200C16D4/8GX',
        slot_index: 1,
        virtual_points: 750,
      },
    ],
    storage_drives: [
      {
        hash: 'd4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef03',
        model: 'Samsung SSD 970 EVO Plus 1TB',
        serial: 'S4EWNF0M123456',
        capacity_bytes: 1000204886016,
        bus_type: 'NVMe',
        is_system_drive: true,
        virtual_points: 2500,
      },
    ],
    motherboard: {
      hash: 'e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef04',
      manufacturer: 'ASUSTeK COMPUTER INC.',
      product: 'ROG STRIX B460-F GAMING',
      serial: '200570192801234',
      virtual_points: 2500,
    },
  },
  virtual_nodes: {
    system_fabric: {
      hash: 'f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345',
      bus_type: 'PCIe 3.0 x16',
      virtual_points: 1500,
    },
    memory_controller: {
      hash: '0718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456',
      channels: 2,
      total_capacity_bytes: 17179869184, // 16GB
      virtual_points: 1000,
    },
    storage_controller: {
      hash: '18293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567',
      total_drives: 1,
      virtual_points: 500,
    },
  },
  tier_hashes: {
    tier1_components: {
      cpu: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
      ram_0: 'b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01',
      ram_1: 'c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef02',
      storage_0: 'd4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef03',
      motherboard: 'e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef04',
    },
    tier2_real_nodes: '22222222e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier3_virtual_nodes: '33333333e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier4_physical_layer: '44444444e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier4_fabric_layer: '44444445e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier5_graph_topology: '55555555e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier6_state_hash: '66666666e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
  },
  summary: {
    total_virtual_points: 13000,
    real_nodes_count: 5,
    virtual_nodes_count: 3,
  },
};

export const MOCK_GRAPH_MUTATED_RAM: CanonicalGraphJson = {
  ...MOCK_GRAPH_BASELINE,
  version: 2,
  real_nodes: {
    ...MOCK_GRAPH_BASELINE.real_nodes,
    ram_dimms: [
      {
        hash: 'b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01',
        capacity_bytes: 8589934592,
        speed_mhz: 3200,
        part_number: 'KHX3200C16D4/8GX',
        slot_index: 0,
        virtual_points: 750,
      },
      {
        hash: 'c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef02',
        capacity_bytes: 8589934592,
        speed_mhz: 3200,
        part_number: 'KHX3200C16D4/8GX',
        slot_index: 1,
        virtual_points: 750,
      },
      {
        hash: 'f9e8d7c6b5a40312123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef99',
        capacity_bytes: 17179869184, // 16GB thêm mới
        speed_mhz: 3200,
        part_number: 'CORSAIR-VENGEANCE-16G',
        slot_index: 2,
        virtual_points: 1500,
      },
    ],
  },
  virtual_nodes: {
    ...MOCK_GRAPH_BASELINE.virtual_nodes,
    memory_controller: {
      hash: '8888293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456',
      channels: 2,
      total_capacity_bytes: 34359738368, // 32GB
      virtual_points: 1500,
    },
  },
  tier_hashes: {
    ...MOCK_GRAPH_BASELINE.tier_hashes,
    tier5_graph_topology: '55555555bbbbbbbb293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    tier6_state_hash: '66666666bbbbbbbb293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
  },
};

export const INITIAL_MOCK_DEVICES: Device[] = [
  {
    id: 'd1-uuid-0001',
    user_id: 'u1-uuid-enterprise',
    device_id: '550e8400-e29b-41d4-a716-446655440001',
    public_key: 'e2b3c4d5f6a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456',
    current_graph_hash: '55555555e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_state_hash: '66666666e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_graph_version: 1,
    status: 'ACTIVE',
    risk_level: 'LOW',
    created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
    updated_at: new Date(Date.now() - 120000).toISOString(),
    last_seen_at: new Date(Date.now() - 45000).toISOString(), // 45 giây trước
  },
  {
    id: 'd2-uuid-0002',
    user_id: 'u1-uuid-enterprise',
    device_id: '660e8400-e29b-41d4-a716-446655440002',
    public_key: 'f3c4d5e6a2b3c4d5e6f708192a3b4c5d6e7f80123456789abcdef0123456789a',
    current_graph_hash: '77777777e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_state_hash: '88888888e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_graph_version: 1,
    status: 'PENDING',
    risk_level: 'MEDIUM',
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    updated_at: new Date(Date.now() - 300000).toISOString(),
    last_seen_at: new Date(Date.now() - 300000).toISOString(),
  },
  {
    id: 'd3-uuid-0003',
    user_id: 'u1-uuid-enterprise',
    device_id: '770e8400-e29b-41d4-a716-446655440003',
    public_key: '04d5e6f7a3b4c5d6e7f8091a2b3c4d5e6f708123456789abcdef0123456789ab',
    current_graph_hash: '99999999e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_state_hash: 'aaaaaaaae5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    current_graph_version: 3,
    status: 'REVOKED',
    risk_level: 'CRITICAL',
    created_at: new Date(Date.now() - 86400000 * 14).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 2).toISOString(),
    last_seen_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
];

export const INITIAL_MOCK_REQUESTS: ReenrollmentRequest[] = [
  {
    id: 'req-uuid-0001',
    device_id: '660e8400-e29b-41d4-a716-446655440002',
    user_id: 'u1-uuid-enterprise',
    previous_state_hash: '88888888e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    new_state_hash: '66666666bbbbbbbb293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    new_graph_hash: '55555555bbbbbbbb293a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0',
    new_graph_version: 2,
    new_graph_json: MOCK_GRAPH_MUTATED_RAM,
    risk_score: 1500, // 15.00%
    risk_level: 'MEDIUM',
    decision: 'REQUIRES_USER_APPROVAL',
    reason: 'RAM module added and capacity upgraded from 16GB to 32GB',
    proof_signature: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d',
    status: 'PENDING',
    created_at: new Date(Date.now() - 600000).toISOString(),
    modified_components: [
      'RAM Slot 2: Gắn thêm Corsair Vengeance 16GB DDR4-3200',
      'Memory Controller: Dung lượng tổng tăng 16GB -> 32GB',
    ],
  },
];

export const INITIAL_MOCK_EVENTS: DeviceEvent[] = [
  {
    id: 'ev-001',
    device_id: '550e8400-e29b-41d4-a716-446655440001',
    event_type: 'ATTESTATION_VERIFIED',
    event_version: 1,
    metadata: {
      state_hash_verified: true,
      latency_ms: 18,
      nonce_consumed: true,
    },
    created_at: new Date(Date.now() - 45000).toISOString(),
  },
  {
    id: 'ev-002',
    device_id: '660e8400-e29b-41d4-a716-446655440002',
    event_type: 'REENROLL_REQUESTED',
    event_version: 1,
    metadata: {
      risk_score: 1500,
      risk_level: 'MEDIUM',
      decision: 'REQUIRES_USER_APPROVAL',
      version_target: 2,
    },
    created_at: new Date(Date.now() - 600000).toISOString(),
  },
  {
    id: 'ev-003',
    device_id: '550e8400-e29b-41d4-a716-446655440001',
    event_type: 'CHALLENGE_ISSUED',
    event_version: 1,
    metadata: {
      nonce_prefix: '7f9a2e...',
      ttl_seconds: 60,
    },
    created_at: new Date(Date.now() - 105000).toISOString(),
  },
  {
    id: 'ev-004',
    device_id: '770e8400-e29b-41d4-a716-446655440003',
    event_type: 'DEVICE_REVOKED',
    event_version: 1,
    metadata: {
      reason: 'Critical hardware mismatch: Motherboard and CPU swapped simultaneously',
      revoked_by: 'u1-uuid-enterprise',
    },
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: 'ev-005',
    device_id: '550e8400-e29b-41d4-a716-446655440001',
    event_type: 'DEVICE_ENROLLED',
    event_version: 1,
    metadata: {
      graph_version: 1,
      public_key_algorithm: 'Ed25519',
      hasher: 'SHA-512',
    },
    created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
];
