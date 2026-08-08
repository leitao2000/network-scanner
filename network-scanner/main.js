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
    // 开发模式自动打开 DevTools
    if (process.env.NODE_ENV === 'development' || process.argv.includes('--dev')) {
      mainWindow.webContents.openDevTools({ mode: 'detach' });
    }
  });

  // 快捷键 F12 / Ctrl+Shift+I 打开/关闭 DevTools
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.type === 'keyDown') {
      if (input.key === 'F12' || (input.control && input.shift && input.key.toLowerCase() === 'i')) {
        mainWindow.webContents.toggleDevTools();
        event.preventDefault();
      }
      // Ctrl+R 刷新页面
      if (input.control && input.key.toLowerCase() === 'r') {
        mainWindow.reload();
        event.preventDefault();
      }
    }
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
  const formatNames = { pdf: 'PDF 报告', html: 'HTML 网页', csv: 'CSV 表格', json: 'JSON 数据', xlsx: 'Excel 表格' };

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

    } else if (filePath.endsWith('.xlsx')) {
      // Excel 表格（带样式）
      const ExcelJS = require('exceljs');
      const wb = new ExcelJS.Workbook();
      const ws = wb.addWorksheet('设备详情');

      // 标题行
      ws.mergeCells('A1:I1');
      const titleCell = ws.getCell('A1');
      titleCell.value = '网络扫描报告';
      titleCell.font = { size: 16, bold: true, color: { argb: 'FF0F172A' } };
      titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
      ws.getRow(1).height = 36;

      // 信息行
      ws.mergeCells('A2:I2');
      const infoCell = ws.getCell('A2');
      const onlineCount = devices.filter(d => d.status === '在线').length;
      infoCell.value = `网段: ${data.cidr || '-'}  |  在线: ${onlineCount}/${devices.length}  |  耗时: ${data.elapsed ? (data.elapsed/1000).toFixed(1) : '-'}s  |  时间: ${new Date().toLocaleString('zh-CN')}`;
      infoCell.font = { size: 11, color: { argb: 'FF64748B' } };
      infoCell.alignment = { horizontal: 'center' };
      ws.getRow(2).height = 24;

      // 表头
      const headers = ['IP 地址', 'MAC 地址', '主机名', '设备类型', '分类', '状态', '延迟', '探测方式', '开放端口'];
      const headerRow = ws.getRow(4);
      headers.forEach((h, i) => {
        const cell = headerRow.getCell(i + 1);
        cell.value = h;
        cell.font = { bold: true, size: 11, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF475569' } };
        cell.alignment = { horizontal: 'center', vertical: 'middle' };
        cell.border = { top: { style: 'thin', color: { argb: 'FFE2E8F0' } }, bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } } };
      });
      ws.getRow(4).height = 28;

      // 数据行
      const catLabels = { phone: '手机', computer: '电脑', router: '路由器', camera: '摄像头', iot: 'IoT', virtual: '虚拟', unknown: '未知' };
      const riskStyles = {
        high: { bg: 'FFFEE2E2', font: 'FFEF4444' },
        medium: { bg: 'FFFEF3C7', font: 'FFF59E0B' },
        low: { bg: 'FFDCFCE7', font: 'FF22C55E' }
      };

      devices.forEach((d, idx) => {
        const row = ws.getRow(5 + idx);
        const vals = [
          d.ip || '',
          d.mac ? d.mac.toUpperCase() : '',
          d.hostname || '',
          d.type || '',
          d.category ? (catLabels[d.category] || d.category) : '',
          d.status || '',
          d.latency != null ? d.latency + ' ms' : '',
          d.method === 'icmp' ? 'ICMP Ping' : d.method === 'tcp' ? 'TCP 端口' : (d.method || ''),
          (d.services || []).map(s => `${s.port} ${s.name}${s.risk === 'high' ? ' [高危]' : s.risk === 'medium' ? ' [中危]' : ''}`).join('\n') || ''
        ];

        vals.forEach((v, i) => {
          const cell = row.getCell(i + 1);
          cell.value = v;
          cell.font = { size: 11, color: { argb: 'FF334155' } };
          cell.alignment = { vertical: 'top', wrapText: true, ...(i < 5 ? { horizontal: 'left' } : { horizontal: 'center' }) };
          cell.border = { bottom: { style: 'thin', color: { argb: 'FFF1F5F9' } } };
        });

        // 在线状态着色
        const statusCell = row.getCell(6);
        if (d.status === '在线') {
          statusCell.font = { size: 11, bold: true, color: { argb: 'FF22C55E' } };
        }

        // 斑马纹
        if (idx % 2 === 1) {
          for (let i = 1; i <= 9; i++) {
            row.getCell(i).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF8FAFC' } };
          }
        }
      });

      // 列宽
      ws.columns = [
        { width: 15 }, { width: 18 }, { width: 16 }, { width: 16 }, { width: 8 },
        { width: 8 }, { width: 10 }, { width: 12 }, { width: 45 }
      ];

      // 冻结表头
      ws.views = [{ state: 'frozen', ySplit: 4 }];

      await wb.xlsx.writeFile(filePath);

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

// ── AI 模型配置与分析 ──────────────────────────
const AI_CONFIG_FILE = path.join(app.getPath('userData'), 'ai-config.json');

// 读取 AI 配置
ipcMain.handle('ai:getConfig', async () => {
  try {
    const fs = require('fs');
    if (fs.existsSync(AI_CONFIG_FILE)) {
      const raw = fs.readFileSync(AI_CONFIG_FILE, 'utf8');
      return JSON.parse(raw);
    }
  } catch (e) { /* ignore */ }
  return null;
});

// 保存 AI 配置
ipcMain.handle('ai:saveConfig', async (event, config) => {
  try {
    const fs = require('fs');
    fs.writeFileSync(AI_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// 测试 AI 连通性
ipcMain.handle('ai:testConnection', async (event, config) => {
  try {
    const https = require('https');
    const http = require('http');
    const isAnthropic = config.baseUrl.toLowerCase().includes('anthropic');

    let urlStr, postData, headers;
    if (isAnthropic) {
      const anthBase = config.baseUrl.replace(/\/+$/, '');
      urlStr = anthBase + (anthBase.includes('/v1') ? '/messages' : '/v1/messages');
      postData = JSON.stringify({
        model: config.model,
        messages: [{ role: 'user', content: '回复"连接成功"四个字' }],
        max_tokens: 20
      });
      headers = {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01'
      };
    } else {
      urlStr = config.baseUrl.replace(/\/+$/, '') + '/chat/completions';
      postData = JSON.stringify({
        model: config.model,
        messages: [{ role: 'user', content: '回复"连接成功"四个字' }],
        max_tokens: 20,
        temperature: 0
      });
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`
      };
    }

    const urlObj = new URL(urlStr);
    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;
    headers['Content-Length'] = Buffer.byteLength(postData);

    return await new Promise((resolve, reject) => {
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + (urlObj.search || ''),
        method: 'POST',
        headers: headers
      };

      const req = lib.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ success: true, status: res.statusCode });
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
          }
        });
      });
      req.on('error', (e) => reject(new Error(e.message)));
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('请求超时（10s）')); });
      req.write(postData);
      req.end();
    });
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// 获取服务商可用模型列表
ipcMain.handle('ai:fetchModels', async (event, config) => {
  try {
    const https = require('https');
    const http = require('http');
    const baseUrl = config.baseUrl.replace(/\/+$/, '');
    const isAnthropic = config.baseUrl.toLowerCase().includes('anthropic');

    // 智谱 OpenAI 兼容端点用 /models，Anthropic 兼容端点用 /v1/models
    const urlStr = isAnthropic
      ? baseUrl + (baseUrl.includes('/v1') ? '/models' : '/v1/models')
      : baseUrl + '/models';
    const urlObj = new URL(urlStr);
    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;

    const models = await new Promise((resolve, reject) => {
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + (urlObj.search || ''),
        method: 'GET',
        headers: isAnthropic
          ? { 'x-api-key': config.apiKey, 'anthropic-version': '2023-06-01' }
          : { 'Authorization': `Bearer ${config.apiKey}` }
      };

      const req = lib.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const j = JSON.parse(body);
              // OpenAI 格式: { data: [{ id: "gpt-4o", ... }] }
              // Anthropic 格式: { data: [{ id: "claude-...", ... }] }
              // 智谱格式: { data: [{ id: "glm-4", ... }] }
              let list = [];
              if (Array.isArray(j.data)) {
                list = j.data.map(m => m.id || m.name).filter(Boolean);
              } else if (Array.isArray(j.models)) {
                list = j.models.map(m => typeof m === 'string' ? m : (m.id || m.name)).filter(Boolean);
              } else if (Array.isArray(j)) {
                list = j.map(m => typeof m === 'string' ? m : (m.id || m.name)).filter(Boolean);
              }
              resolve(list.sort());
            } catch (e) {
              reject(new Error('解析模型列表失败: ' + e.message));
            }
          } else {
            let msg = `HTTP ${res.statusCode}`;
            try {
              const ej = JSON.parse(body);
              if (ej.error?.message) msg += ': ' + ej.error.message;
              else if (ej.message) msg += ': ' + ej.message;
            } catch (_) {
              if (body) msg += ': ' + body.slice(0, 200);
            }
            reject(new Error(msg));
          }
        });
      });
      req.on('error', (e) => reject(new Error(e.message)));
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('请求超时（10s）')); });
      req.end();
    });

    return { success: true, models };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// AI 分析设备
ipcMain.handle('ai:analyzeDevice', async (event, { device, localInfo, scanContext }) => {
  let config;
  try {
    const fs = require('fs');
    if (fs.existsSync(AI_CONFIG_FILE)) {
      config = JSON.parse(fs.readFileSync(AI_CONFIG_FILE, 'utf8'));
    }
  } catch (e) { /* ignore */ }
  if (!config || !config.apiKey || !config.baseUrl || !config.model) {
    return { success: false, error: 'AI 模型未配置，请先在设置中配置 API Key、端点和模型名称' };
  }

  // 构造 prompt
  const svcs = (device.services || []).map(s => {
    const port = typeof s === 'object' ? s.port : s;
    const name = typeof s === 'object' ? s.name : (PORT_SVC_NAMES[port] || 'unknown');
    const risk = typeof s === 'object' ? s.risk : 'low';
    const desc = typeof s === 'object' ? (s.desc || '') : '';
    return `  - 端口 ${port} (${name})，风险等级: ${risk === 'high' ? '高危' : risk === 'medium' ? '中危' : '低危'}${desc ? '，' + desc : ''}`;
  }).join('\n') || '  - 无开放端口';

  const alerts = (scanContext?.alerts || []).map(a => `  - [${a.level === 'high' ? '高危' : '中危'}] ${a.title}: ${a.detail || ''}`).join('\n') || '  - 无告警';

  const deviceInfo = {
    ip: device.ip,
    mac: device.mac || '未知',
    hostname: device.hostname || '未知',
    type: device.type || '未知',
    category: device.category || 'unknown',
    latency: device.latency != null ? device.latency + 'ms' : '未知',
    method: device.method || '未知',
    status: device.status || '未知',
    openPorts: svcs,
    alerts: alerts,
    subnet: scanContext?.cidr || '未知',
    localIp: localInfo?.ip || '未知',
    gateway: localInfo?.gateway || '未知'
  };

  const prompt = `你是一位资深网络安全分析师。请根据以下局域网扫描设备信息，从"用户画像"和"安全风险"两个维度进行分析。

## 设备信息
- IP 地址: ${deviceInfo.ip}
- MAC 地址: ${deviceInfo.mac}
- 主机名: ${deviceInfo.hostname}
- 设备类型/分类: ${deviceInfo.type} / ${deviceInfo.category}
- 网络状态: ${deviceInfo.status}，延迟 ${deviceInfo.latency}，探测方式 ${deviceInfo.method}
- 所属网段: ${deviceInfo.subnet}
- 本机 IP: ${deviceInfo.localIp}，网关: ${deviceInfo.gateway}

## 开放端口
${deviceInfo.openPorts}

## 安全告警
${deviceInfo.alerts}

## 输出要求
请用中文，按以下 Markdown 格式输出（不要输出其他内容）：

### 用户画像
推测该设备的使用者身份、用途场景、技术水平等。

### 安全风险
列出风险点并给出风险等级（高/中/低），包括端口暴露、协议安全、权限风险等。

### 建议措施
给出 3-5 条具体可操作的安全加固建议。`;

  try {
    const https = require('https');
    const http = require('http');

    // 检测 API 类型：URL 包含 anthropic 则使用 Anthropic 格式，否则 OpenAI
    const isAnthropic = config.baseUrl.toLowerCase().includes('anthropic');

    // 多字段兼容解析（适配各种 OpenAI 兼容中间件）
    const extractChoiceText = (json) => {
      if (!json) return null;
      if (json.type === 'content_block_delta' && json.delta?.text) return json.delta.text;
      if (json.type === 'message_start' && json.message?.content?.[0]?.text) return json.message.content[0].text;
      if (json.type === 'message_delta' && json.delta?.text) return json.delta.text;
      if (Array.isArray(json.content)) {
        const texts = json.content.filter(c => c && c.type === 'text' && c.text).map(c => c.text);
        if (texts.length) return texts.join('');
      }
      if (typeof json.content === 'string' && json.content) return json.content;
      const ch0 = json.choices && json.choices[0];
      if (ch0) {
        if (typeof ch0.delta?.content === 'string' && ch0.delta.content) return ch0.delta.content;
        if (typeof ch0.message?.content === 'string' && ch0.message.content) return ch0.message.content;
        if (typeof ch0.text === 'string' && ch0.text) return ch0.text;
        if (typeof ch0.content === 'string' && ch0.content) return ch0.content;
      }
      if (typeof json.text === 'string' && json.text) return json.text;
      if (typeof json.output === 'string' && json.output) return json.output;
      if (typeof json.answer === 'string' && json.answer) return json.answer;
      if (typeof json.result === 'string' && json.result) return json.result;
      return null;
    };

    // 发送 HTTP 请求的辅助函数
    function doRequest(urlStr, headers, postData, timeoutMs) {
      const urlObj = new URL(urlStr);
      const isHttps = urlObj.protocol === 'https:';
      const lib = isHttps ? https : http;

      return new Promise((resolve, reject) => {
        const options = {
          hostname: urlObj.hostname,
          port: urlObj.port || (isHttps ? 443 : 80),
          path: urlObj.pathname + (urlObj.search || ''),
          method: 'POST',
          headers: { ...headers, 'Content-Length': Buffer.byteLength(postData) }
        };

        const req = lib.request(options, (res) => {
          let body = '';
          res.on('data', (chunk) => { body += chunk.toString(); });
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, body });
          });
        });

        req.on('error', (e) => reject(new Error(e.message)));
        req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`请求超时（${timeoutMs / 1000}s）`)); });
        req.write(postData);
        req.end();
      });
    }

    const baseUrl = config.baseUrl.replace(/\/+$/, '');

    // ── 第一步：直接用非流式请求（最可靠） ──
    let urlStr, postData, headers;

    if (isAnthropic) {
      urlStr = baseUrl + (baseUrl.includes('/v1') ? '/messages' : '/v1/messages');
      postData = JSON.stringify({
        model: config.model,
        system: '你是一位专业的网络安全分析师，擅长分析局域网设备的安全风险。请使用中文回答，输出 Markdown 格式。',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: Math.min(config.maxTokens || 2000, 4096),
        stream: false
      });
      headers = {
        'Content-Type': 'application/json',
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01'
      };
    } else {
      urlStr = baseUrl + '/chat/completions';
      postData = JSON.stringify({
        model: config.model,
        messages: [
          { role: 'system', content: '你是一位专业的网络安全分析师，擅长分析局域网设备的安全风险。请使用中文回答，输出 Markdown 格式。' },
          { role: 'user', content: prompt }
        ],
        max_tokens: config.maxTokens || 2000,
        temperature: config.temperature || 0.7,
        stream: false
      });
      headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`
      };
    }

    const res = await doRequest(urlStr, headers, postData, 60000);

    // 非 2xx 错误
    if (res.statusCode < 200 || res.statusCode >= 300) {
      let msg = `HTTP ${res.statusCode}`;
      try {
        const j = JSON.parse(res.body);
        if (j.error?.message) msg += ': ' + j.error.message;
        else if (j.message) msg += ': ' + j.message;
      } catch (_) {
        if (res.body) msg += ': ' + res.body.slice(0, 300);
      }
      return { success: false, error: msg };
    }

    // 解析非流式 JSON 响应
    let fullText = '';
    try {
      const j = JSON.parse(res.body);
      fullText = extractChoiceText(j) || '';
    } catch (_) {
      // 响应不是 JSON，可能是纯文本
      if (res.body && res.body.trim()) fullText = res.body.trim();
    }

    // 如果非流式拿到了内容，直接返回
    if (fullText) {
      // 模拟流式推送（一次性推全部内容，让前端有"打字机"效果）
      if (mainWindow && !mainWindow.isDestroyed()) {
        const chunks = fullText.match(/[\s\S]{1,20}/g) || [fullText];
        for (const chunk of chunks) {
          mainWindow.webContents.send('ai:streamChunk', chunk);
        }
      }
      return { success: true, content: fullText };
    }

    // ── 第二步：非流式也没拿到内容，尝试流式请求 ──
    let streamPostData;
    if (isAnthropic) {
      streamPostData = JSON.stringify({
        model: config.model,
        system: '你是一位专业的网络安全分析师，擅长分析局域网设备的安全风险。请使用中文回答，输出 Markdown 格式。',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: Math.min(config.maxTokens || 2000, 4096),
        stream: true
      });
    } else {
      streamPostData = JSON.stringify({
        model: config.model,
        messages: [
          { role: 'system', content: '你是一位专业的网络安全分析师，擅长分析局域网设备的安全风险。请使用中文回答，输出 Markdown 格式。' },
          { role: 'user', content: prompt }
        ],
        max_tokens: config.maxTokens || 2000,
        temperature: config.temperature || 0.7,
        stream: true
      });
    }

    const streamRes = await doRequest(urlStr, headers, streamPostData, 60000);

    if (streamRes.statusCode < 200 || streamRes.statusCode >= 300) {
      let msg = `HTTP ${streamRes.statusCode}`;
      try {
        const j = JSON.parse(streamRes.body);
        if (j.error?.message) msg += ': ' + j.error.message;
      } catch (_) {
        if (streamRes.body) msg += ': ' + streamRes.body.slice(0, 300);
      }
      return { success: false, error: msg };
    }

    // 解析流式响应
    let streamText = '';
    let streamEmpty = true;
    const lines = streamRes.body.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(': ')) continue;
      if (!trimmed.startsWith('data: ')) continue;
      const data = trimmed.slice(6);
      if (data === '[DONE]') continue;
      try {
        const json = JSON.parse(data);
        const delta = extractChoiceText(json);
        if (delta) {
          streamEmpty = false;
          streamText += delta;
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('ai:streamChunk', delta);
          }
        }
      } catch (e) { /* skip */ }
    }

    // 流式也解析不出，尝试拼接整体
    if (streamEmpty && streamRes.body.trim()) {
      try {
        let cleaned = streamRes.body;
        if (cleaned.includes('data: ')) {
          cleaned = cleaned.split('\n').map(l => l.trim())
            .filter(l => l.startsWith('data: ') && l.slice(6) !== '[DONE]')
            .map(l => l.slice(6)).join('');
        }
        if (cleaned) {
          const j = JSON.parse(cleaned);
          streamText = extractChoiceText(j) || '';
        }
      } catch (_) { /* ignore */ }
      if (!streamText) {
        try {
          const rawJ = JSON.parse(streamRes.body);
          streamText = extractChoiceText(rawJ) || '';
        } catch (_) { /* ignore */ }
      }
    }

    if (streamText) {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('ai:streamChunk', streamText);
      }
      return { success: true, content: streamText };
    }

    return { success: false, error: 'AI 返回内容为空。\n请检查：\n1. 模型名称是否正确\n2. API Key 是否有效\n3. 端点 URL 是否正确\n4. 账户是否有余额/额度\n\n响应原文（前500字符）：\n' + (res.body || streamRes.body || '').slice(0, 500) };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

const PORT_SVC_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP',
  443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
  1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
};
