// Electron 主进程
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const Scanner = require('./scanner');

let mainWindow = null;
let currentScanner = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    title: '本地网络扫描工具',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    },
    show: false,
    titleBarStyle: 'default'
  });

  mainWindow.loadFile(path.join(__dirname, 'pages', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// 获取本机网络信息
ipcMain.handle('network:getLocalInfo', async () => {
  return Scanner.getLocalInfo();
});

// 扫描指定网段
ipcMain.handle('network:scan', async (event, options) => {
  if (currentScanner) {
    return { success: false, error: '已有扫描任务进行中' };
  }

  const scanner = new Scanner();
  currentScanner = scanner;

  scanner.on('progress', (data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('network:scanProgress', data);
    }
  });

  scanner.on('device', (device) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('network:scanDevice', device);
    }
  });

  scanner.on('deviceUpdate', (device) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('network:scanDeviceUpdate', device);
    }
  });

  try {
    const result = await scanner.scanNetwork(options);
    return { success: true, ...result };
  } catch (error) {
    return { success: false, error: error.message };
  } finally {
    if (currentScanner === scanner) {
      currentScanner = null;
    }
  }
});

// 停止扫描
ipcMain.handle('network:stopScan', async () => {
  if (currentScanner) {
    currentScanner.stop();
    return { success: true };
  }
  return { success: false, error: '没有正在进行的扫描' };
});

// 获取 ARP 缓存
ipcMain.handle('network:getArpTable', async () => {
  return Scanner.getArpTable();
});

// 端口扫描
ipcMain.handle('network:scanPorts', async (event, { host, ports }) => {
  const scanner = new Scanner();
  try {
    const openPorts = await scanner.scanPorts(host, ports);
    return { success: true, openPorts };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// 导出结果
ipcMain.handle('network:export', async (event, data) => {
  if (!mainWindow || mainWindow.isDestroyed()) return { success: false, error: '窗口已关闭' };

  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: '导出扫描结果',
    defaultPath: `scan-result-${Date.now()}.json`,
    filters: [
      { name: 'JSON 文件', extensions: ['json'] },
      { name: 'CSV 文件', extensions: ['csv'] }
    ]
  });

  if (!filePath) return { success: false, canceled: true };

  try {
    const fs = require('fs');
    if (filePath.endsWith('.csv')) {
      const lines = ['IP,MAC,Hostname,Type,Status,Latency'];
      for (const device of data.devices || []) {
        lines.push(`${device.ip},${device.mac || ''},${device.hostname || ''},${device.type || ''},${device.status || ''},${device.latency != null ? device.latency : ''}`);
      }
      fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
    } else {
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    }
    return { success: true, filePath };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// 打开管理员权限提示
ipcMain.handle('app:requestElevation', async () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: '需要管理员权限',
    message: '完整的 ARP / ICMP 扫描通常需要以管理员身份运行本应用。',
    buttons: ['知道了']
  });
});
