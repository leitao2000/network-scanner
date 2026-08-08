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
  }
});
