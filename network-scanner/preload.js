// Electron preload 脚本 - 安全暴露主进程 API 给渲染进程
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // 获取本机网络信息
  getLocalInfo: () => ipcRenderer.invoke('network:getLocalInfo'),

  // 开始扫描网段
  scanNetwork: (options) => ipcRenderer.invoke('network:scan', options),

  // 停止扫描
  stopScan: () => ipcRenderer.invoke('network:stopScan'),

  // 获取 ARP 表
  getArpTable: () => ipcRenderer.invoke('network:getArpTable'),

  // 端口扫描
  scanPorts: (host, ports) => ipcRenderer.invoke('network:scanPorts', { host, ports }),

  // 单次 Ping
  pingHost: (host, timeout) => ipcRenderer.invoke('network:pingHost', { host, timeout }),

  // 导出结果
  exportResult: (data) => ipcRenderer.invoke('network:export', data),

  // 请求管理员提示
  requestElevation: () => ipcRenderer.invoke('app:requestElevation'),

  // 关于软件
  showAbout: () => ipcRenderer.invoke('app:showAbout'),

  // AI 模型配置
  aiGetConfig: () => ipcRenderer.invoke('ai:getConfig'),
  aiSaveConfig: (config) => ipcRenderer.invoke('ai:saveConfig', config),
  aiTestConnection: (config) => ipcRenderer.invoke('ai:testConnection', config),
  aiAnalyzeDevice: (data) => ipcRenderer.invoke('ai:analyzeDevice', data),
  aiFetchModels: (config) => ipcRenderer.invoke('ai:fetchModels', config),
  onAiStreamChunk: (callback) => {
    const wrapped = (event, chunk) => callback(chunk);
    ipcRenderer.on('ai:streamChunk', wrapped);
    return () => ipcRenderer.removeListener('ai:streamChunk', wrapped);
  },

  // 监听扫描进度
  onScanProgress: (callback) => {
    const wrapped = (event, data) => callback(data);
    ipcRenderer.on('network:scanProgress', wrapped);
    return () => ipcRenderer.removeListener('network:scanProgress', wrapped);
  },

  // 监听发现设备
  onScanDevice: (callback) => {
    const wrapped = (event, device) => callback(device);
    ipcRenderer.on('network:scanDevice', wrapped);
    return () => ipcRenderer.removeListener('network:scanDevice', wrapped);
  },

  // 监听设备信息更新（如扫描结束后补充 MAC）
  onScanDeviceUpdate: (callback) => {
    const wrapped = (event, device) => callback(device);
    ipcRenderer.on('network:scanDeviceUpdate', wrapped);
    return () => ipcRenderer.removeListener('network:scanDeviceUpdate', wrapped);
  },

  // ── 网络诊断工具扩展 ──
  traceroute: (host, maxHops, timeout) => ipcRenderer.invoke('network:traceroute', { host, maxHops, timeout }),
  wakeOnLan: (mac, broadcast) => ipcRenderer.invoke('network:wakeOnLan', { mac, broadcast }),
  scanUdpPorts: (host, ports, timeout) => ipcRenderer.invoke('network:scanUdpPorts', { host, ports, timeout }),
  scanPortsAdvanced: (host, ports, options) => ipcRenderer.invoke('network:scanPortsAdvanced', { host, ports, options }),
  detectOs: (device) => ipcRenderer.invoke('network:detectOs', { device }),
  resolveDns: (hostname, server) => ipcRenderer.invoke('network:resolveDns', { hostname, server }),
  reverseDns: (ip, server) => ipcRenderer.invoke('network:reverseDns', { ip, server }),
  speedTest: (host, options) => ipcRenderer.invoke('network:speedTest', { host, options }),
  remoteShutdown: (host, options) => ipcRenderer.invoke('network:remoteShutdown', { host, options }),

  // ── 设备元数据持久化（备注/标签/收藏/分组） ──
  deviceMetaGetAll: () => ipcRenderer.invoke('devicemeta:getAll'),
  deviceMetaSave: (device, meta) => ipcRenderer.invoke('devicemeta:save', { device, meta }),
  deviceMetaDelete: (device) => ipcRenderer.invoke('devicemeta:delete', { device }),
  deviceMetaAddGroup: (name) => ipcRenderer.invoke('devicemeta:addGroup', { name }),
  deviceMetaRemoveGroup: (name) => ipcRenderer.invoke('devicemeta:removeGroup', { name }),
  deviceMetaGetGroups: () => ipcRenderer.invoke('devicemeta:getGroups'),

  // ── 扫描历史数据库持久化（JSON 文件） ──
  historyDbGet: (limit) => ipcRenderer.invoke('historydb:get', { limit }),
  historyDbSave: (record) => ipcRenderer.invoke('historydb:save', { record }),
  historyDbClear: () => ipcRenderer.invoke('historydb:clear'),
  historyDbDelete: (id) => ipcRenderer.invoke('historydb:delete', { id })
});
