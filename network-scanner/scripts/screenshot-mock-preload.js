// 截图专用 mock preload —— 用虚构数据替代真实网络 API，避免把真实局域网信息截进公开截图
const { contextBridge } = require('electron');

// ── 虚构的演示数据（非真实设备） ─────────────────────────────
const mockAdapter = {
  name: 'WLAN',
  cidr: '192.168.31.0/24',
  address: '192.168.31.100',
  netmask: '255.255.255.0',
  broadcast: '192.168.31.255',
  gateway: '192.168.31.1',
  mac: 'a4:bb:6d:1a:2b:3c'
};

const mockLocalInfo = {
  hostname: 'DESKTOP-7F3K2Q',
  platform: 'win32',
  adapters: [mockAdapter, {
    name: 'VMware Network Adapter VMnet1',
    cidr: '192.168.88.0/24',
    address: '192.168.88.1',
    netmask: '255.255.255.0',
    broadcast: '192.168.88.255',
    gateway: null,
    mac: '00:50:56:c0:00:01'
  }],
  activeAdapter: mockAdapter
};

const mockDevices = [
  { ip: '192.168.31.1',   mac: 'D4:EE:07:5A:B1:0C', hostname: 'router.lan',      type: 'TP-Link 路由器',  category: 'router',  status: '在线', latency: 1.8,  method: 'icmp',
    services: [{ port: 80, name: 'HTTP 管理界面', desc: 'Web 管理后台', risk: 'low' }, { port: 443, name: 'HTTPS', desc: 'Web 管理后台(TLS)', risk: 'low' }] },
  { ip: '192.168.31.100', mac: 'A4:BB:6D:1A:2B:3C', hostname: 'DESKTOP-7F3K2Q', type: '本机',            category: 'computer', status: '在线', latency: 0.6,  method: 'icmp', services: [] },
  { ip: '192.168.31.102', mac: 'F8:8A:06:3C:91:D4', hostname: 'WORKSTATION-X1', type: 'Dell 电脑',      category: 'computer', status: '在线', latency: 3.2,  method: 'icmp',
    services: [{ port: 445, name: 'SMB', desc: 'Windows 文件共享', risk: 'medium' }, { port: 3389, name: 'RDP', desc: '远程桌面', risk: 'medium' }] },
  { ip: '192.168.31.107', mac: 'AC:DE:48:9F:22:71', hostname: 'iphone-of-leo',  type: 'Apple 手机',     category: 'phone',   status: '在线', latency: 12.5, method: 'icmp', services: [] },
  { ip: '192.168.31.110', mac: '64:CC:2E:88:04:19', hostname: 'Redmi-Note12',   type: 'Xiaomi 手机',    category: 'phone',   status: '在线', latency: 18.9, method: 'icmp', services: [] },
  { ip: '192.168.31.120', mac: '00:11:32:4A:7D:55', hostname: 'nas-home',       type: 'Synology NAS',   category: 'computer', status: '在线', latency: 2.4,  method: 'icmp',
    services: [{ port: 5001, name: 'HTTPS', desc: 'Synology DSM', risk: 'low' }, { port: 445, name: 'SMB', desc: '文件共享', risk: 'medium' }] },
  { ip: '192.168.31.130', mac: 'B8:27:EB:31:9C:06', hostname: 'raspberrypi',    type: 'Raspberry Pi',   category: 'iot',     status: '在线', latency: 4.7,  method: 'icmp',
    services: [{ port: 22, name: 'SSH', desc: 'OpenSSH', risk: 'medium' }, { port: 8090, name: 'HTTP', desc: 'Web 服务', risk: 'low' }] },
  { ip: '192.168.31.135', mac: '9C:8E:CD:20:61:8A', hostname: 'ipcamera-living', type: '网络摄像头',    category: 'camera',  status: '在线', latency: 9.1,  method: 'icmp',
    services: [{ port: 554, name: 'RTSP', desc: '视频流', risk: 'high' }] },
  { ip: '192.168.31.140', mac: '',                 hostname: '',                type: '在线设备',       category: 'unknown', status: '在线', latency: 36.0, method: 'tcp', services: [] }
];

const listeners = { progress: [], device: [], deviceUpdate: [] };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function mockScanNetwork() {
  const total = 254;
  const t0 = Date.now();
  const emit = (key, payload) => listeners[key].forEach(cb => { try { cb(payload); } catch {} });

  emit('progress', { phase: 'started', scanned: 0, total, found: 0, elapsed: 0 });
  await sleep(600);

  // 模拟逐段扫描进度，并让设备逐步上屏（截图「扫描中」状态用）
  const milestones = [40, 105, 170, 230, 254];
  let found = 0;
  for (let i = 0; i < milestones.length; i++) {
    await sleep(700);
    const scanned = milestones[i];
    found = Math.min(mockDevices.length, found + 2);
    for (let j = 0; j < Math.min(found, mockDevices.length); j++) {
      emit('device', mockDevices[j]);
    }
    emit('progress', { phase: 'scanning', scanned, total, found: Math.min(found, mockDevices.length), elapsed: Date.now() - t0 });
  }

  await sleep(500);
  emit('progress', { phase: 'portscanning', scanned: total, total, found: mockDevices.length, elapsed: Date.now() - t0 });
  await sleep(800);
  emit('progress', { phase: 'completed', scanned: total, total, found: mockDevices.length, elapsed: Date.now() - t0 });

  return { success: true, devices: mockDevices, elapsed: Date.now() - t0 };
}

const noop = async () => ({ success: true });
const noopArr = async () => ({ success: true, records: [], devices: {}, groups: [] });

contextBridge.exposeInMainWorld('electronAPI', {
  getLocalInfo: async () => mockLocalInfo,
  scanNetwork: mockScanNetwork,
  stopScan: noop,

  onScanProgress: (cb) => { listeners.progress.push(cb); return () => {}; },
  onScanDevice: (cb) => { listeners.device.push(cb); return () => {}; },
  onScanDeviceUpdate: (cb) => { listeners.deviceUpdate.push(cb); return () => {}; },

  getArpTable: async () => ({ success: true, table: [] }),
  scanPorts: async () => ({ success: true, ports: [] }),
  pingHost: async () => ({ success: true, alive: true, latency: 3.2 }),
  exportResult: noop,
  requestElevation: noop,
  showAbout: noop,

  aiGetConfig: async () => ({ success: true, config: null }),
  aiSaveConfig: noop,
  aiTestConnection: async () => ({ success: true }),
  aiAnalyzeDevice: noop,
  aiFetchModels: async () => ({ success: true, models: [] }),
  onAiStreamChunk: () => () => {},

  traceroute: async () => ({ success: true, hops: [] }),
  wakeOnLan: noop,
  scanUdpPorts: async () => ({ success: true, ports: [] }),
  scanPortsAdvanced: async () => ({ success: true, ports: [] }),
  detectOs: async () => ({ success: true, os: 'Windows' }),
  resolveDns: async () => ({ success: true, addresses: [] }),
  reverseDns: async () => ({ success: true, hostname: '' }),
  speedTest: async () => ({ success: true }),
  remoteShutdown: noop,

  deviceMetaGetAll: async () => ({ devices: {}, groups: [] }),
  deviceMetaSave: noop,
  deviceMetaDelete: noop,
  deviceMetaAddGroup: noop,
  deviceMetaRemoveGroup: noop,
  deviceMetaGetGroups: async () => ({ success: true, groups: [] }),

  historyDbGet: async () => ({ records: [] }),
  historyDbSave: noop,
  historyDbClear: noop,
  historyDbDelete: noop
});
