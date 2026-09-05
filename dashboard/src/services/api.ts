// ====================================================================
// CyberV Device-Binding Security Protocol: API Service Facade
// Seamless Dual-Mode: Live Supabase PostgREST & Edge Functions + Demo State
// ====================================================================

import { supabase, isLiveConfigured } from './supabase';
import type {
  Device,
  ReenrollmentRequest,
  DeviceEvent,
  CanonicalGraphJson,
} from '../types/device';
import {
  INITIAL_MOCK_DEVICES,
  INITIAL_MOCK_REQUESTS,
  INITIAL_MOCK_EVENTS,
  MOCK_GRAPH_BASELINE,
  MOCK_GRAPH_MUTATED_RAM,
} from './mockData';

class ApiService {
  private isDemoMode: boolean = !isLiveConfigured();
  private mockDevices: Device[] = [...INITIAL_MOCK_DEVICES];
  private mockRequests: ReenrollmentRequest[] = [...INITIAL_MOCK_REQUESTS];
  private mockEvents: DeviceEvent[] = [...INITIAL_MOCK_EVENTS];
  private subscribers: Array<() => void> = [];

  constructor() {
    // Check localStorage preference if any
    const savedMode = localStorage.getItem('cyberv_demo_mode');
    if (savedMode !== null) {
      this.isDemoMode = savedMode === 'true';
    } else {
      this.isDemoMode = !isLiveConfigured();
    }
  }

  public getIsDemoMode(): boolean {
    return this.isDemoMode;
  }

  public setDemoMode(val: boolean) {
    this.isDemoMode = val;
    localStorage.setItem('cyberv_demo_mode', String(val));
    this.notifySubscribers();
  }

  public subscribe(cb: () => void) {
    this.subscribers.push(cb);
    return () => {
      this.subscribers = this.subscribers.filter((s) => s !== cb);
    };
  }

  private notifySubscribers() {
    this.subscribers.forEach((cb) => cb());
  }

  // --- Devices ---
  public async getDevices(): Promise<Device[]> {
    if (this.isDemoMode || !supabase) {
      return [...this.mockDevices];
    }
    const { data, error } = await supabase
      .from('devices')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  }

  // --- Device Graph ---
  public async getDeviceGraph(deviceId: string, version: number): Promise<CanonicalGraphJson> {
    if (this.isDemoMode || !supabase) {
      if (version > 1) {
        return { ...MOCK_GRAPH_MUTATED_RAM, device_id: deviceId, version };
      }
      return { ...MOCK_GRAPH_BASELINE, device_id: deviceId, version };
    }
    const { data, error } = await supabase
      .from('device_graphs')
      .select('canonical_graph_json')
      .eq('device_id', deviceId)
      .eq('graph_version', version)
      .single();
    if (error || !data) {
      return { ...MOCK_GRAPH_BASELINE, device_id: deviceId, version };
    }
    return data.canonical_graph_json;
  }

  // --- Re-enrollment Requests ---
  public async getReenrollmentRequests(): Promise<ReenrollmentRequest[]> {
    if (this.isDemoMode || !supabase) {
      return [...this.mockRequests];
    }
    const { data, error } = await supabase
      .from('re_enrollment_requests')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  }

  // --- Approve Re-enrollment ---
  public async approveReenrollment(requestId: string): Promise<{ success: boolean; message: string }> {
    if (this.isDemoMode || !supabase) {
      const reqIndex = this.mockRequests.findIndex((r) => r.id === requestId);
      if (reqIndex === -1) throw new Error('Request not found');

      const req = this.mockRequests[reqIndex];
      req.status = 'APPROVED';
      req.reviewed_at = new Date().toISOString();

      // Update target device
      const devIndex = this.mockDevices.findIndex((d) => d.device_id === req.device_id);
      if (devIndex !== -1) {
        this.mockDevices[devIndex] = {
          ...this.mockDevices[devIndex],
          current_graph_version: req.new_graph_version,
          current_graph_hash: req.new_graph_hash,
          current_state_hash: req.new_state_hash,
          status: 'ACTIVE',
          risk_level: 'LOW',
          updated_at: new Date().toISOString(),
          last_seen_at: new Date().toISOString(),
        };
      }

      // Add audit event
      this.mockEvents.unshift({
        id: 'ev-' + Date.now(),
        device_id: req.device_id,
        event_type: 'REENROLL_USER_APPROVED',
        event_version: 1,
        metadata: {
          request_id: requestId,
          new_graph_version: req.new_graph_version,
          new_state_hash: req.new_state_hash,
          promoted_by: 'Dashboard Admin',
          timestamp: new Date().toISOString(),
        },
        created_at: new Date().toISOString(),
      });

      this.notifySubscribers();
      return { success: true, message: 'Yêu cầu Tái cấp quyền đã được phê duyệt thành công.' };
    }

    // Live mode: Call Edge Function
    const { data, error } = await supabase.functions.invoke('re-enroll-approve', {
      body: { request_id: requestId, action: 'APPROVE' },
    });
    if (error) throw error;
    this.notifySubscribers();
    return data;
  }

  // --- Reject Re-enrollment ---
  public async rejectReenrollment(requestId: string): Promise<{ success: boolean; message: string }> {
    if (this.isDemoMode || !supabase) {
      const reqIndex = this.mockRequests.findIndex((r) => r.id === requestId);
      if (reqIndex === -1) throw new Error('Request not found');

      const req = this.mockRequests[reqIndex];
      req.status = 'REJECTED';
      req.reviewed_at = new Date().toISOString();

      // Add audit event
      this.mockEvents.unshift({
        id: 'ev-' + Date.now(),
        device_id: req.device_id,
        event_type: 'REENROLL_USER_REJECTED',
        event_version: 1,
        metadata: {
          request_id: requestId,
          reason: 'User rejected hardware mutation on dashboard',
          timestamp: new Date().toISOString(),
        },
        created_at: new Date().toISOString(),
      });

      this.notifySubscribers();
      return { success: true, message: 'Yêu cầu Tái cấp quyền đã bị từ chối.' };
    }

    const { data, error } = await supabase.functions.invoke('re-enroll-approve', {
      body: { request_id: requestId, action: 'REJECT' },
    });
    if (error) throw error;
    this.notifySubscribers();
    return data;
  }

  // --- Revoke Device ---
  public async revokeDevice(deviceId: string, reason?: string): Promise<{ success: boolean; message: string }> {
    if (this.isDemoMode || !supabase) {
      const devIndex = this.mockDevices.findIndex((d) => d.device_id === deviceId);
      if (devIndex === -1) throw new Error('Device not found');

      this.mockDevices[devIndex] = {
        ...this.mockDevices[devIndex],
        status: 'REVOKED',
        risk_level: 'CRITICAL',
        updated_at: new Date().toISOString(),
      };

      this.mockEvents.unshift({
        id: 'ev-' + Date.now(),
        device_id: deviceId,
        event_type: 'DEVICE_REVOKED',
        event_version: 1,
        metadata: {
          reason: reason || 'Thu hồi thiết bị tức thì từ Web Dashboard',
          revoked_by: 'Dashboard User',
          timestamp: new Date().toISOString(),
        },
        created_at: new Date().toISOString(),
      });

      this.notifySubscribers();
      return { success: true, message: 'Thiết bị đã bị thu hồi quyền truy cập thành công.' };
    }

    const { data, error } = await supabase.functions.invoke('revoke-device', {
      body: { device_id: deviceId, reason },
    });
    if (error) throw error;
    this.notifySubscribers();
    return data;
  }

  // --- Audit Events ---
  public async getDeviceEvents(deviceId?: string): Promise<DeviceEvent[]> {
    if (this.isDemoMode || !supabase) {
      if (deviceId) {
        return this.mockEvents.filter((e) => e.device_id === deviceId);
      }
      return [...this.mockEvents];
    }
    let query = supabase.from('device_events').select('*').order('created_at', { ascending: false });
    if (deviceId) {
      query = query.eq('device_id', deviceId);
    }
    const { data, error } = await query;
    if (error) throw error;
    return data || [];
  }
}

export const apiService = new ApiService();
