import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import type { TabType } from './components/Sidebar';
import { OverviewTab } from './components/OverviewTab';
import { DeviceListTab } from './components/DeviceListTab';
import { HardwareGraphVisualizer } from './components/HardwareGraphVisualizer';
import { ReenrollmentQueueTab } from './components/ReenrollmentQueueTab';
import { AuditTimelineTab } from './components/AuditTimelineTab';
import { RevokeModal } from './components/RevokeModal';
import { AuthModal } from './components/AuthModal';
import type { Device, ReenrollmentRequest, DeviceEvent, UserSession } from './types/device';
import { apiService } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabType>('overview');
  const [devices, setDevices] = useState<Device[]>([]);
  const [requests, setRequests] = useState<ReenrollmentRequest[]>([]);
  const [events, setEvents] = useState<DeviceEvent[]>([]);
  const [selectedDeviceForGraph, setSelectedDeviceForGraph] = useState<Device | null>(null);
  const [deviceToRevoke, setDeviceToRevoke] = useState<Device | null>(null);
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isDemo, setIsDemo] = useState<boolean>(apiService.getIsDemoMode());

  const [user, setUser] = useState<UserSession | null>(() => {
    return {
      user_id: 'u1-uuid-enterprise',
      email: 'security.officer@cyberv.internal',
      role: 'SecOps Enterprise Admin',
      is_demo: true,
    };
  });

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [devList, reqList, evList] = await Promise.all([
        apiService.getDevices(),
        apiService.getReenrollmentRequests(),
        apiService.getDeviceEvents(),
      ]);
      setDevices(devList);
      setRequests(reqList);
      setEvents(evList);
      if (!selectedDeviceForGraph && devList.length > 0) {
        setSelectedDeviceForGraph(devList[0]);
      }
    } catch (err: any) {
      console.error('Failed to load CyberV data:', err);
    } finally {
      setIsLoading(false);
    }
  }, [selectedDeviceForGraph]);

  useEffect(() => {
    loadData();
    const unsubscribe = apiService.subscribe(() => {
      setIsDemo(apiService.getIsDemoMode());
      loadData();
    });
    return unsubscribe;
  }, [loadData]);

  const pendingRequestsCount = requests.filter((r) => r.status === 'PENDING').length;

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        pendingCount={pendingRequestsCount}
        totalDevices={devices.length}
      />

      {/* Main View Container */}
      <div className="app-main">
        {/* Sticky Header */}
        <Header
          user={user}
          isDemo={isDemo}
          onRefresh={loadData}
          onOpenAuth={() => setShowAuthModal(true)}
          onLogout={() => setUser(null)}
          isLoading={isLoading}
        />

        {/* Dynamic Tab Body */}
        <main className="app-content">
          {currentTab === 'overview' && (
            <OverviewTab
              devices={devices}
              requests={requests}
              events={events}
              onNavigate={setCurrentTab}
              onSelectDeviceForGraph={(dev) => {
                setSelectedDeviceForGraph(dev);
                setCurrentTab('graph');
              }}
            />
          )}

          {currentTab === 'devices' && (
            <DeviceListTab
              devices={devices}
              onSelectDeviceForGraph={(dev) => {
                setSelectedDeviceForGraph(dev);
                setCurrentTab('graph');
              }}
              onOpenRevokeModal={setDeviceToRevoke}
            />
          )}

          {currentTab === 'graph' && (
            <HardwareGraphVisualizer
              devices={devices}
              selectedDevice={selectedDeviceForGraph}
              onSelectDevice={setSelectedDeviceForGraph}
            />
          )}

          {currentTab === 'reenroll' && (
            <ReenrollmentQueueTab
              requests={requests}
              onActionComplete={loadData}
            />
          )}

          {currentTab === 'events' && (
            <AuditTimelineTab events={events} />
          )}
        </main>
      </div>

      {/* Revocation Confirmation Modal */}
      {deviceToRevoke && (
        <RevokeModal
          device={deviceToRevoke}
          onClose={() => setDeviceToRevoke(null)}
          onSuccess={loadData}
        />
      )}

      {/* Authentication Modal */}
      {showAuthModal && (
        <AuthModal
          onClose={() => setShowAuthModal(false)}
          onSuccess={(session) => {
            setUser(session);
            loadData();
          }}
        />
      )}
    </div>
  );
};

export default App;
