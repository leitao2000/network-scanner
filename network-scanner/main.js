// Electron 主进程
const { app, BrowserWindow, ipcMain, dialog, shell, Menu } = require('electron');
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
    title: '本地网络扫描工具 v1.0.0',
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
  // 移除默认菜单栏（File/Edit/View/Window/Help）
  Menu.setApplicationMenu(null);

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

// 单次 Ping
ipcMain.handle('network:pingHost', async (event, { host, timeout }) => {
  const scanner = new Scanner();
  try {
    const result = await scanner.pingOnce(host, timeout || 2000);
    return { success: true, ...result };
  } catch (error) {
    return { success: false, alive: false, latency: null, error: error.message };
  }
});

// 导出结果
ipcMain.handle('network:export', async (event, data) => {
  if (!mainWindow || mainWindow.isDestroyed()) return { success: false, error: '窗口已关闭' };

  const format = data.format || 'pdf';
  const dateStr = new Date().toISOString().slice(0, 10);
  const formatNames = { pdf: 'PDF 报告', html: 'HTML 网页', csv: 'CSV 表格', json: 'JSON 数据' };

  const { filePath } = await dialog.showSaveDialog(mainWindow, {
    title: '导出扫描报告',
    defaultPath: `scan-report-${dateStr}.${format}`,
    filters: [{ name: `${formatNames[format] || '文件'} (*.${format})`, extensions: [format] }]
  });

  if (!filePath) return { success: false, canceled: true };

  try {
    const fs = require('fs');
    const devices = data.devices || [];

    if (filePath.endsWith('.csv')) {
      const lines = ['IP,MAC,Hostname,Type,Category,Status,Latency,Method,OpenPorts'];
      for (const d of devices) {
        const ports = (d.services || []).map(s => typeof s === 'object' ? s.port : s).join(';');
        lines.push(`${d.ip},${d.mac || ''},${d.hostname || ''},${(d.type || '').replace(/,/g, ';')},${d.category || ''},${d.status || ''},${d.latency != null ? d.latency : ''},${d.method || ''},${ports}`);
      }
      fs.writeFileSync(filePath, '\uFEFF' + lines.join('\n'), 'utf8');

    } else if (filePath.endsWith('.json')) {
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');

    } else if (filePath.endsWith('.pdf')) {
      // PDF：用隐藏窗口渲染 HTML 再 printToPDF
      const html = generateHtmlReport(data);
      const pdfWin = new BrowserWindow({
        show: false,
        webPreferences: { offscreen: true }
      });
      await pdfWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
      await new Promise(r => setTimeout(r, 500)); // 等渲染完成
      const pdfBuffer = await pdfWin.webContents.printToPDF({
        pageSize: 'A4',
        printBackground: true,
        landscape: true,
        margins: { top: 0.4, bottom: 0.4, left: 0.4, right: 0.4 }
      });
      fs.writeFileSync(filePath, pdfBuffer);
      pdfWin.destroy();

    } else {
      // HTML 详细报告
      const html = generateHtmlReport(data);
      fs.writeFileSync(filePath, html, 'utf8');
    }
    return { success: true, filePath };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

function generateHtmlReport(data) {
  const devices = data.devices || [];
  const now = new Date();
  const dateStr = now.toLocaleString('zh-CN');
  const elapsed = data.elapsed ? (data.elapsed / 1000).toFixed(1) : '-';
  const onlineCount = devices.filter(d => d.status === '在线').length;
  const totalPorts = devices.reduce((sum, d) => sum + (d.services ? d.services.length : 0), 0);
  const highRisk = devices.reduce((sum, d) => sum + (d.services || []).filter(s => s.risk === 'high').length, 0);

  const riskColors = { high: '#ef4444', medium: '#f59e0b', low: '#22c55e' };
  const riskLabels = { high: '高危', medium: '中危', low: '低危' };
  const catLabels = { phone: '手机', computer: '电脑', router: '路由器', camera: '摄像头', iot: 'IoT', virtual: '虚拟', unknown: '未知' };

  const deviceRows = devices.map(d => {
    const ports = (d.services || []).map(s => `
      <span style="display:inline-block; margin:2px 4px 2px 0; padding:2px 8px; border-radius:4px; font-size:12px; background:${riskColors[s.risk] || riskColors.low}15; color:${riskColors[s.risk] || riskColors.low}; border:1px solid ${riskColors[s.risk] || riskColors.low}40;">
        <strong>${s.port}</strong> ${s.name}${s.desc ? ' · ' + s.desc : ''} <span style="font-size:10px;">[${riskLabels[s.risk] || '低危'}]</span>
      </span>`).join('');

    return `
      <tr>
        <td style="font-family:monospace; font-weight:600; color:#1e293b;">${d.ip}</td>
        <td style="font-family:monospace; color:#475569;">${d.mac ? d.mac.toUpperCase() : '—'}</td>
        <td style="color:#475569;">${d.hostname || '—'}</td>
        <td style="color:#475569;">${d.type || '—'}</td>
        <td style="text-align:center;">${d.category ? `<span style="font-size:11px; padding:2px 8px; border-radius:999px; background:#f1f5f9; color:#475569;">${catLabels[d.category] || d.category}</span>` : '—'}</td>
        <td style="text-align:center; color:${d.status === '在线' ? '#22c55e' : '#94a3b8'}; font-weight:600;">${d.status || '—'}</td>
        <td style="text-align:center; color:#475569;">${d.latency != null ? d.latency + ' ms' : '—'}</td>
        <td style="color:#64748b; font-size:12px;">${d.method === 'icmp' ? 'ICMP Ping' : d.method === 'tcp' ? 'TCP 端口' : d.method || '—'}</td>
        <td>${ports || '<span style="color:#cbd5e1;">—</span>'}</td>
      </tr>`;
  }).join('');

  // 统计分类
  const catStats = {};
  for (const d of devices) {
    const c = d.category || 'unknown';
    catStats[c] = (catStats[c] || 0) + 1;
  }
  const catBadges = Object.entries(catStats).map(([k, v]) =>
    `<span style="display:inline-block; margin-right:8px; padding:4px 12px; border-radius:6px; background:#f1f5f9; font-size:13px; color:#475569;">${catLabels[k] || k}：${v}</span>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>网络扫描报告 - ${dateStr}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #f8fafc; color: #1e293b; padding: 32px; }
    .header { text-align: center; padding: 32px 0; border-bottom: 2px solid #e2e8f0; margin-bottom: 24px; }
    .header h1 { font-size: 28px; color: #0f172a; margin-bottom: 8px; }
    .header .subtitle { font-size: 14px; color: #94a3b8; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: #fff; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.06); border: 1px solid #f1f5f9; }
    .stat-card .num { font-size: 32px; font-weight: 700; color: #0f172a; }
    .stat-card .label { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .stat-card.danger .num { color: #ef4444; }
    .stat-card.warn .num { color: #f59e0b; }
    .stat-card.success .num { color: #22c55e; }
    .section { background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); border: 1px solid #f1f5f9; }
    .section h2 { font-size: 18px; color: #0f172a; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; }
    .info-row { display: flex; padding: 6px 0; font-size: 14px; }
    .info-row .lbl { width: 140px; color: #94a3b8; flex-shrink: 0; }
    .info-row .val { color: #334155; }
    .cat-distribution { padding: 8px 0; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 10px 12px; background: #f8fafc; color: #64748b; font-weight: 600; border-bottom: 2px solid #e2e8f0; white-space: nowrap; }
    td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
    tr:hover td { background: #fafbfc; }
    .footer { text-align: center; padding: 24px 0; color: #94a3b8; font-size: 12px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>网络扫描报告</h1>
    <div class="subtitle">生成时间：${dateStr}</div>
  </div>

  <div class="stats">
    <div class="stat-card success">
      <div class="num">${onlineCount}</div>
      <div class="label">在线设备</div>
    </div>
    <div class="stat-card">
      <div class="num">${devices.length}</div>
      <div class="label">扫描发现</div>
    </div>
    <div class="stat-card warn">
      <div class="num">${totalPorts}</div>
      <div class="label">开放端口</div>
    </div>
    <div class="stat-card danger">
      <div class="num">${highRisk}</div>
      <div class="label">高危端口</div>
    </div>
  </div>

  <div class="section">
    <h2>扫描信息</h2>
    <div class="info-row"><span class="lbl">扫描网段</span><span class="val" style="font-family:monospace;">${data.cidr || '-'}</span></div>
    <div class="info-row"><span class="lbl">耗时</span><span class="val">${elapsed} 秒</span></div>
    <div class="info-row"><span class="lbl">生成时间</span><span class="val">${dateStr}</span></div>
    <div class="cat-distribution">${catBadges}</div>
  </div>

  <div class="section">
    <h2>设备详情（${devices.length} 台）</h2>
    <table>
      <thead>
        <tr>
          <th>IP 地址</th>
          <th>MAC 地址</th>
          <th>主机名</th>
          <th>设备类型</th>
          <th>分类</th>
          <th>状态</th>
          <th>延迟</th>
          <th>探测方式</th>
          <th>开放端口</th>
        </tr>
      </thead>
      <tbody>
        ${deviceRows}
      </tbody>
    </table>
  </div>

  <div class="footer">
    本报告由 网络扫描工具 自动生成 · ${dateStr}
  </div>
</body>
</html>`;
}

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

// 关于软件
ipcMain.handle('app:showAbout', async () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: '关于本地网络扫描',
    message: '本地网络扫描工具',
    detail: '版本：1.0.0\n功能：局域网设备扫描、拓扑绘制、端口探测、安全告警\n\n作者：网络运维团队\n感谢使用本工具！',
    buttons: ['确定']
  });
});
