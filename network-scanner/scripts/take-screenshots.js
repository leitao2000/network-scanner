// 自动截图脚本：加载真实界面 + mock 数据，逐视图截屏输出 PNG
// 用法：npx electron scripts/take-screenshots.js
const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..');                 // network-scanner/
const OUT_DIR = path.join(ROOT, '..', 'docs', 'images'); // 仓库 docs/images/

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function capture(win, name) {
  const image = await win.webContents.capturePage();
  const file = path.join(OUT_DIR, name);
  fs.writeFileSync(file, image.toPNG());
  console.log('[saved]', file, `${image.getSize().width}x${image.getSize().height}`);
}

async function run() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  Menu.setApplicationMenu(null);

  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'screenshot-mock-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  await win.loadFile(path.join(ROOT, 'pages', 'index.html'));
  await sleep(1500); // 等待 init / 图标渲染

  const js = (code) => win.webContents.executeJavaScript(code);

  // 1. 开始扫描
  await js(`document.getElementById('btn-start').click()`);
  await sleep(2600); // 扫描进行中（约中段，设备逐步上屏）
  await capture(win, 'scanning.png');

  // 2. 等待扫描完成
  await sleep(6000);
  await capture(win, 'dashboard.png');

  // 3. 切到拓扑视图
  await js(`document.getElementById('tab-topology').click()`);
  await sleep(1200);
  await capture(win, 'topology.png');

  // 4. 回到设备列表，打开路由器详情抽屉
  await js(`document.getElementById('tab-devicelist').click()`);
  await sleep(400);
  await js(`document.querySelector('tr[data-ip="192.168.31.1"]').click()`);
  await sleep(1200);
  await capture(win, 'device-detail.png');

  win.destroy();
  app.quit();
}

app.whenReady().then(run).catch(err => {
  console.error(err);
  app.exit(1);
});
