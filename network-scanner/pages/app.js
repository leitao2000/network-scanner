(() => {
  const api = window.electronAPI;

  // State
  let localInfo = null;
  let selectedAdapter = null;
  let currentMode = 'standard';
  let currentFilter = 'all';
  let isScanning = false;
  let devices = [];
  let scanStartTime = 0;
  let scanTimer = null;
  let searchQuery = '';
  let scanPromise = null;

  // 新增状态
  let currentDetailDevice = null;
  let monitorTimer = null;
  let monitorStats = { success: 0, total: 0, latencies: [], history: [] };
  let activeAlerts = [];

  const modeConfig = {
    quick: { label: '快速', concurrency: 80, timeout: 800 },
    standard: { label: '标准', concurrency: 50, timeout: 1200 },
    deep: { label: '深度', concurrency: 25, timeout: 3000 },
    ai: { label: 'AI', concurrency: 50, timeout: 1500 }
  };

  // 常见端口 -> 服务名映射
  const PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
  };
  const PORT_DESCRIPTIONS = {
    21:   '文件传输协议，用于上传/下载文件',
    22:   '安全远程登录与命令执行',
    23:   '明文远程登录，不安全',
    25:   '邮件发送服务',
    53:   '域名解析服务',
    80:   'Web 管理页面或网站服务',
    110:  '邮件接收服务',
    135:  'Windows 远程过程调用',
    139:  'Windows 文件共享/名称服务',
    143:  '邮件接收服务（同步）',
    443:  '加密 Web 管理页面或网站服务',
    445:  'Windows 文件/打印机共享，易受攻击',
    993:  '加密邮件接收服务',
    995:  '加密邮件接收服务',
    1433: 'Microsoft SQL Server 数据库',
    1521: 'Oracle 数据库监听端口',
    3306: 'MySQL 数据库服务',
    3389: 'Windows 远程桌面连接',
    5432: 'PostgreSQL 数据库',
    5900: 'VNC 远程桌面',
    6379: 'Redis 缓存数据库',
    8080: '备用 Web 端口（代理/管理页）',
    8443: '备用加密 Web 端口',
    27017: 'MongoDB 文档数据库'
  };
  // 高危端口（暴露在局域网即告警）
  const HIGH_RISK_PORTS = [23, 445, 3389, 5900, 21];
  const MED_RISK_PORTS = [22, 1433, 1521, 3306, 5432, 6379, 27017];

  const HISTORY_KEY = 'network_scanner_history';
  const BASELINE_KEY = 'network_scanner_baseline';
  const HISTORY_MAX = 20;

  // DOM refs
  const els = {
    localIp: document.getElementById('local-ip'),
    localPrefix: document.getElementById('local-prefix'),
    localGateway: document.getElementById('local-gateway'),
    localNetmask: document.getElementById('local-netmask'),
    localBroadcast: document.getElementById('local-broadcast'),
    localHostCount: document.getElementById('local-host-count'),
    localHostname: document.getElementById('local-hostname'),
    localMac: document.getElementById('local-mac'),
    localDns: document.getElementById('local-dns'),
    localCidr: document.getElementById('local-cidr'),
    adapterCount: document.getElementById('adapter-count'),
    adapterList: document.getElementById('adapter-list'),
    scanTarget: document.getElementById('scan-target'),
    scanHostCount: document.getElementById('scan-host-count'),
    scanRange: document.getElementById('scan-range'),
    scanHosts: document.getElementById('scan-hosts'),
    scanMode: document.getElementById('scan-mode'),
    scanFound: document.getElementById('scan-found'),
    scanElapsed: document.getElementById('scan-elapsed'),
    scanProgress: document.getElementById('scan-progress'),
    btnStart: document.getElementById('btn-start'),
    btnStop: document.getElementById('btn-stop'),
    btnExport: document.getElementById('btn-export'),
    statDevices: document.getElementById('stat-devices'),
    statOnline: document.getElementById('stat-online'),
    statLatency: document.getElementById('stat-latency'),
    statTime: document.getElementById('stat-time'),
    statFingerprints: document.getElementById('stat-fingerprints'),
    statEvidence: document.getElementById('stat-evidence'),
    deviceCount: document.getElementById('device-count'),
    deviceCidr: document.getElementById('device-cidr'),
    deviceTableBody: document.getElementById('device-table-body'),
    emptyState: document.getElementById('empty-state'),
    searchInput: document.getElementById('search-input')
  };

  function setText(el, text) {
    if (el) el.textContent = text;
  }

  function parseCidrHosts(cidr) {
    const [, prefix] = cidr.split('/');
    const p = parseInt(prefix, 10);
    if (p === 32) return 1;
    if (p === 31) return 2;
    return Math.pow(2, 32 - p) - 2;
  }

  function cidrRange(cidr) {
    const [ip, prefix] = cidr.split('/');
    const p = parseInt(prefix, 10);
    const ipInt = ip.split('.').reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0;
    const mask = 0xffffffff << (32 - p);
    const net = ipInt & mask;
    const intToIp = (int) => [(int >>> 24) & 0xff, (int >>> 16) & 0xff, (int >>> 8) & 0xff, int & 0xff].join('.');

    if (p === 32) return intToIp(net);
    if (p === 31) return `${intToIp(net)} - ${intToIp(net + 1)}`;

    const first = net + 1;
    const last = net + Math.pow(2, 32 - p) - 2;
    return `${intToIp(first)} - ${intToIp(last)}`;
  }

  function inferGateway(cidr, realGateway) {
    if (realGateway) return realGateway;
    const [ip, prefix] = cidr.split('/');
    const p = parseInt(prefix, 10);
    const ipInt = ip.split('.').reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0;
    const mask = 0xffffffff << (32 - p);
    const net = ipInt & mask;
    const intToIp = (int) => [(int >>> 24) & 0xff, (int >>> 16) & 0xff, (int >>> 8) & 0xff, int & 0xff].join('.');
    if (p === 32) return intToIp(net);
    return intToIp(net + 1);
  }

  function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  function renderLocalInfo() {
    if (!localInfo || !selectedAdapter) return;
    const a = selectedAdapter;
    const hosts = parseCidrHosts(a.cidr);

    setText(els.localIp, a.address);
    setText(els.localPrefix, `/${a.cidr.split('/')[1]}`);
    setText(els.localGateway, inferGateway(a.cidr, a.gateway));
    setText(els.localNetmask, a.netmask);
    setText(els.localBroadcast, a.broadcast);
    setText(els.localHostCount, hosts.toString());
    setText(els.localHostname, localInfo.hostname);
    setText(els.localMac, a.mac.toUpperCase());
    setText(els.localDns, a.gateway || inferGateway(a.cidr));
    setText(els.localCidr, a.cidr);

    setText(els.adapterCount, localInfo.adapters.length.toString());
    els.adapterList.innerHTML = '';

    for (const adapter of localInfo.adapters) {
      const isActive = adapter.address === a.address;
      const isVirtual = /vmware|virtualbox|vbox|hyper-v|docker/i.test(adapter.name);
      const btn = document.createElement('button');
      btn.className = `w-full text-left rounded-lg border p-3 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
        isActive
          ? 'border-primary bg-primary/5 hover:bg-primary/10'
          : 'border-border bg-card hover:bg-muted'
      }`;
      btn.innerHTML = `
        <div class="flex items-center gap-2 mb-1">
          <i data-lucide="${isVirtual ? 'network' : 'wifi'}" class="w-4 h-4 ${isActive ? 'text-primary' : 'text-muted-foreground'}"></i>
          <span class="text-sm font-medium text-foreground truncate">${adapter.name}</span>
          ${isActive ? '<span class="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-primary text-primary-foreground">当前</span>' : ''}
        </div>
        <div class="text-xs text-muted-foreground scanner-mono">${adapter.cidr}</div>
      `;
      btn.addEventListener('click', () => {
        selectedAdapter = adapter;
        renderLocalInfo();
        updateScanTarget();
        clearDevices();
      });
      els.adapterList.appendChild(btn);
    }
    lucide.createIcons();
  }

  function updateScanTarget() {
    if (!selectedAdapter) return;
    const cidr = selectedAdapter.cidr;
    const hosts = parseCidrHosts(cidr);
    els.scanTarget.value = `当前子网 ${cidr}`;
    setText(els.scanHostCount, hosts.toString());
    setText(els.scanRange, cidr);
    setText(els.scanHosts, hosts.toString());
    setText(els.deviceCidr, cidr);
  }

  function updateModeButtons() {
    document.querySelectorAll('.mode-btn').forEach(btn => {
      const mode = btn.dataset.mode;
      if (mode === currentMode) {
        btn.className = 'mode-btn px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground';
      } else {
        btn.className = 'mode-btn px-3 py-1.5 text-xs font-medium rounded text-muted-foreground hover:bg-muted transition';
      }
    });
    setText(els.scanMode, modeConfig[currentMode].label);
  }

  function updateFilterButtons() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
      const filter = btn.dataset.filter;
      if (filter === currentFilter) {
        btn.className = 'filter-btn px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground whitespace-nowrap';
      } else {
        btn.className = 'filter-btn px-3 py-1.5 text-xs font-medium rounded text-muted-foreground hover:bg-muted transition whitespace-nowrap';
      }
    });
  }

  function getDeviceIcon(device) {
    const cat = device.category;
    const type = device.type || '';
    if (type === '本机') return 'laptop';
    if (cat === 'router' || type.includes('路由') || type.includes('网关')) return 'wifi';
    if (cat === 'phone' || type.includes('手机') || type.includes('隐私地址')) return 'smartphone';
    if (cat === 'camera' || type.includes('摄像')) return 'video';
    if (cat === 'iot' || type.includes('Raspberry') || type.includes('Echo') || type.includes('IoT')) return 'cpu';
    if (cat === 'virtual' || type.includes('VMware') || type.includes('VirtualBox') || type.includes('虚拟')) return 'server';
    if (cat === 'computer' || type.includes('电脑') || type.includes('Intel') || type.includes('Dell') || type.includes('HP') || type.includes('Lenovo') || type.includes('ASUS') || type.includes('Microsoft')) return 'monitor';
    return 'monitor';
  }

  function getDeviceTypeBadges(device) {
    const badges = [];
    if (device.type === '本机') badges.push({ text: '本机', cls: 'bg-primary/10 text-primary' });
    else if (device.type) badges.push({ text: device.type, cls: 'bg-muted text-muted-foreground' });
    if (!device.mac) badges.push({ text: 'MAC 缺失', cls: 'bg-muted text-muted-foreground' });
    return badges;
  }

  function deviceMatchesFilter(device, filter) {
    if (filter === 'all') return true;
    if (filter === 'online') return device.status === '在线';
    if (filter === 'services') return device.services && device.services.length > 0;
    if (filter === 'pending') return !device.mac;
    if (filter === 'unknown') return device.type === '在线设备';
    return true;
  }

  function deviceMatchesSearch(device, query) {
    if (!query) return true;
    const q = query.toLowerCase();
    return (
      (device.ip && device.ip.toLowerCase().includes(q)) ||
      (device.hostname && device.hostname.toLowerCase().includes(q)) ||
      (device.mac && device.mac.toLowerCase().includes(q)) ||
      (device.type && device.type.toLowerCase().includes(q))
    );
  }

  function renderDevices() {
    const filtered = devices.filter(d => deviceMatchesFilter(d, currentFilter) && deviceMatchesSearch(d, searchQuery));
    setText(els.deviceCount, filtered.length.toString());

    if (filtered.length === 0) {
      els.deviceTableBody.innerHTML = '';
      els.emptyState.style.display = 'flex';
      return;
    }
    els.emptyState.style.display = 'none';

    els.deviceTableBody.innerHTML = filtered.map(device => {
      const icon = getDeviceIcon(device);
      const iconColor = device.type === '本机' ? 'bg-primary/10 text-primary' : '';
      const iconStyle = device.type === '本机' ? '' : `background: color-mix(in srgb, var(--scanner-state-info) 10%, transparent); color: var(--scanner-state-info);`;
      const badges = getDeviceTypeBadges(device);
      const badgeHtml = badges.map(b => `<span class="text-xs px-2 py-0.5 rounded ${b.cls}">${b.text}</span>`).join('');
      const statusHtml = `<span class="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full" style="background: var(--scanner-state-success-bg); color: var(--scanner-state-success);"><span class="w-1.5 h-1.5 rounded-full bg-current"></span>${device.status}</span>`;
      const hostLine = device.hostname || (device.type === '本机' ? localInfo?.hostname : device.type || '-');
      const macLine = device.mac ? device.mac.toUpperCase() : '—';
      const latency = device.latency != null ? `${device.latency} ms` : '—';
      const services = device.services && device.services.length ? `${device.services.length} 个` : '—';
      return `
        <tr class="border-b border-border hover:bg-muted/40 transition device-row-enter" data-ip="${device.ip}" style="cursor:pointer;">
          <td class="px-4 py-3 align-middle">
            <div class="flex items-center gap-2">
              <div class="w-6 h-6 rounded flex items-center justify-center ${iconColor}" style="${iconStyle}">
                <i data-lucide="${icon}" class="w-3.5 h-3.5"></i>
              </div>
              <span class="font-medium scanner-mono text-foreground">${device.ip}</span>
            </div>
          </td>
          <td class="px-4 py-3 align-middle">${badgeHtml}</td>
          <td class="px-4 py-3 align-middle">${statusHtml}</td>
          <td class="px-4 py-3 align-middle">
            <div class="text-foreground">${hostLine}</div>
            <div class="text-xs scanner-mono text-muted-foreground">${macLine}</div>
          </td>
          <td class="px-4 py-3 align-middle text-muted-foreground">${services}</td>
          <td class="px-4 py-3 align-middle"><span class="scanner-mono text-foreground">${latency}</span></td>
        </tr>
      `;
    }).join('');
    lucide.createIcons();
    renderTopology();
  }

  // ── 网络拓扑图渲染（层级卡片式） ──────────────────
  let topoScale = 1;

  /**
   * 判断设备是否为网络基础设施（AP/交换机/桥接设备）
   * 基于真实网络属性：OUI 厂商、开放端口、延迟特征
   */
  function isNetworkInfrastructure(device, gatewayIp) {
    if (!device) return false;
    // 网关不算中间设备
    if (gatewayIp && device.ip === gatewayIp) return false;
    if (device.category === 'router') return false;
    if (device.type === '本机') return false;

    // 1. 延迟极低（<2ms）且非本机：可能是交换机/桥接设备
    if (device.latency != null && device.latency > 0 && device.latency < 2 && device.method === 'icmp') {
      return true;
    }

    // 2. 开放了网络设备管理端口（23 Telnet / 161 SNMP）且非终端类型
    const services = device.services || [];
    const hasMgmtPort = services.some(s => {
      const p = parseInt(String(s).match(/(\d+)/)?.[1] || '0', 10);
      return p === 23 || p === 161;
    });
    if (hasMgmtPort && device.category !== 'computer' && device.category !== 'phone') {
      return true;
    }

    // 3. OUI 属于已知网络设备厂商（非路由器但生产网络设备）
    if (device.mac) {
      const oui = device.mac.slice(0, 8).toUpperCase();
      // TP-Link/D-Link/Netgear/Huawei/小米 等厂商的非路由器设备可能是 AP
      const infraVendors = ['TP-LINK', 'D-Link', 'Netgear', 'Huawei', 'Xiaomi', 'Cisco', 'H3C', 'Ruijie'];
      if (device.vendor && infraVendors.some(v => device.vendor.toLowerCase().includes(v.toLowerCase()))) {
        // 但手机/电脑不算
        if (device.category !== 'computer' && device.category !== 'phone') {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * 将终端设备按延迟聚类分配到最近的中间设备（AP/交换机）
   * 返回 [{ parent: infraDevice, children: [devices] }]
   */
  function assignToInfrastructures(terminals, infrastructures) {
    const groups = infrastructures.map(infra => ({ parent: infra, children: [] }));
    for (const terminal of terminals) {
      // 找延迟最近的中间设备
      let bestGroup = null;
      let bestDiff = Infinity;
      for (const group of groups) {
        const infraLatency = group.parent.latency || 0;
        const termLatency = terminal.latency || 0;
        // 终端延迟应 >= 中间设备延迟（因为经过中间设备）
        const diff = Math.abs(termLatency - infraLatency);
        if (diff < bestDiff) {
          bestDiff = diff;
          bestGroup = group;
        }
      }
      if (bestGroup) {
        bestGroup.children.push(terminal);
      }
    }
    // 过滤空分组
    return groups.filter(g => g.children.length > 0);
  }

  function renderTopology() {
    const container = document.getElementById('topology-container');
    const canvas = document.getElementById('topology-canvas');
    const nodesEl = document.getElementById('topology-nodes');
    const edgesEl = document.getElementById('topology-edges');
    const emptyEl = document.getElementById('topo-empty');
    const statsEl = document.getElementById('topo-stats');
    const zoomEl = document.getElementById('topo-zoom');
    if (!canvas) return;

    const allDevices = devices;

    if (allDevices.length === 0) {
      nodesEl.innerHTML = '';
      edgesEl.innerHTML = '';
      if (emptyEl) emptyEl.style.display = 'flex';
      if (statsEl) statsEl.style.display = 'none';
      if (zoomEl) zoomEl.style.display = 'none';
      return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    if (statsEl) statsEl.style.display = 'block';
    if (zoomEl) zoomEl.style.display = 'block';

    // 统计数据
    const nodes = allDevices.length;
    const online = allDevices.filter(d => d.status === '在线').length;
    const services = allDevices.reduce((sum, d) => sum + (d.services ? d.services.length : 0), 0);
    setText(document.getElementById('topo-stat-nodes'), nodes.toString());
    setText(document.getElementById('topo-stat-online'), online.toString());
    setText(document.getElementById('topo-stat-services'), services.toString());

    // ── 基于真实网络属性构建拓扑 ──────────────────────
    const gatewayIp = selectedAdapter?.gateway || null;

    // 1. 识别网关：优先 gateway IP，其次 category/type 标记
    const gateway = allDevices.find(d =>
      (gatewayIp && d.ip === gatewayIp) ||
      d.category === 'router' ||
      d.type?.includes('路由') || d.type?.includes('网关')
    ) || null;

    // 2. 识别本机
    const localDevice = allDevices.find(d => d.type === '本机') || {
      ip: selectedAdapter?.address || '127.0.0.1',
      type: '本机',
      hostname: localInfo?.hostname || '本机',
      status: '在线',
      mac: localInfo?.mac || '',
      latency: 0,
      services: []
    };

    // 3. 识别中间网络设备（AP/交换机）：非网关但具有网络设备特征
    //    特征：category 为 iot 且开放 80/443 管理端口，或 OUI 为已知网络设备厂商，
    //    或延迟极低（<3ms，可能是交换机/桥接设备）
    const intermediateDevices = [];
    const terminalSet = new Set();
    for (const d of allDevices) {
      if (d === gateway || d === localDevice || d.type === '本机') continue;
      const isIntermediate = isNetworkInfrastructure(d, gatewayIp);
      if (isIntermediate) {
        intermediateDevices.push(d);
      } else {
        terminalSet.add(d);
      }
    }

    // 4. 终端设备：本机 + 非中间设备
    const terminalDevices = [localDevice, ...Array.from(terminalSet)];

    // 5. 基于延迟聚类：将终端设备分组（延迟接近的设备可能在同一 AP/交换机下）
    //    仅当存在中间设备时才分组，否则所有终端直连网关
    let terminalGroups;
    if (intermediateDevices.length > 0) {
      // 有中间设备：按最近延迟分配到对应中间设备
      terminalGroups = assignToInfrastructures(terminalDevices, intermediateDevices);
    } else {
      // 无中间设备：所有终端直连网关（或本机，若无网关）
      terminalGroups = [{ parent: gateway || localDevice, children: terminalDevices }];
    }

    // 6. 构建层级
    const layers = [];
    const hasGateway = !!gateway;

    // Layer 0: Internet（仅当有网关时）
    if (hasGateway) {
      layers.push([{
        id: 'internet',
        ip: 'Internet',
        type: 'WAN',
        hostname: 'Internet',
        status: '在线',
        isInternet: true
      }]);
    }

    // Layer 1: 网关（或本机，若无网关）
    if (hasGateway) {
      layers.push([gateway]);
    } else if (!layers.length) {
      layers.push([localDevice]);
    }

    // Layer 2: 中间设备（AP/交换机），仅当存在时
    if (intermediateDevices.length > 0) {
      layers.push(intermediateDevices);
    }

    // Layer 3+: 终端设备分组（每组一层，每层最多 5 个）
    const chunkSize = 5;
    for (const group of terminalGroups) {
      const children = group.children.filter(d => d !== group.parent);
      if (children.length === 0) continue;
      for (let i = 0; i < children.length; i += chunkSize) {
        layers.push(children.slice(i, i + chunkSize));
      }
    }

    // 渲染卡片
    const nodeWidth = 180;
    const nodeHeight = 90;
    const layerGap = 60;
    const nodeGap = 20;
    const padding = 40;

    const layerHeights = layers.map(layer => {
      const count = layer.length;
      const totalWidth = count * nodeWidth + (count - 1) * nodeGap;
      return { count, totalWidth };
    });

    const maxWidth = Math.max(...layerHeights.map(l => l.totalWidth), nodeWidth);
    const totalHeight = layers.length * (nodeHeight + layerGap);
    const canvasWidth = maxWidth + padding * 2;
    const canvasHeight = totalHeight + padding * 2;

    canvas.style.width = canvasWidth + 'px';
    canvas.style.height = canvasHeight + 'px';

    // 存储节点位置用于连线
    const nodePositions = {};

    // 生成卡片 HTML
    let cardsHtml = '';
    layers.forEach((layer, layerIdx) => {
      const layerInfo = layerHeights[layerIdx];
      const layerStartX = (canvasWidth - layerInfo.totalWidth) / 2;
      const y = padding + layerIdx * (nodeHeight + layerGap);

      layer.forEach((device, nodeIdx) => {
        const x = layerStartX + nodeIdx * (nodeWidth + nodeGap);
        const posKey = device.isInternet ? 'internet' : (device.ip || `node-${layerIdx}-${nodeIdx}`);
        nodePositions[posKey] = { x: x + nodeWidth / 2, y: y + nodeHeight / 2, left: x, top: y };

        cardsHtml += renderDeviceCard(device, x, y, nodeWidth, nodeHeight);
      });
    });

    nodesEl.innerHTML = cardsHtml;

    // 渲染连线（基于真实父子关系）
    renderEdges(edgesEl, nodePositions, layers, canvasWidth, canvasHeight, hasGateway, terminalGroups, intermediateDevices);

    // 初始化拖拽平移
    initTopoPan(container, canvas);

    // 计算居中偏移
    topoScale = 1;
    const freshContainer = document.getElementById('topology-container');
    if (freshContainer) {
      const containerWidth = freshContainer.clientWidth;
      const containerHeight = freshContainer.clientHeight;
      const scale = Math.min(1, Math.min(
        (containerWidth - 20) / canvasWidth,
        (containerHeight - 20) / canvasHeight
      ));
      topoScale = Math.max(0.5, scale);
      topoPan.x = Math.max(0, (containerWidth - canvasWidth * topoScale) / 2);
      topoPan.y = Math.max(0, (containerHeight - canvasHeight * topoScale) / 2);
    }

    const freshCanvas = document.getElementById('topology-canvas');
    applyTopoTransform(freshCanvas);
  }

  // ── 拓扑图拖拽平移 ──
  let topoPan = { x: 0, y: 0 };
  let isDragging = false;
  let dragStart = { x: 0, y: 0 };
  let panStart = { x: 0, y: 0 };

  function initTopoPan(container, canvas) {
    if (!container || !canvas) return;
    // 移除旧监听器（通过克隆节点）
    const newContainer = container.cloneNode(false);
    while (container.firstChild) {
      newContainer.appendChild(container.firstChild);
    }
    container.parentNode.replaceChild(newContainer, container);

    const curContainer = newContainer;
    const curCanvas = curContainer.querySelector('#topology-canvas');
    if (!curCanvas) return;

    let hasMoved = false;

    curContainer.addEventListener('mousedown', (e) => {
      // 不拦截卡片点击
      if (e.target.closest('.topo-node-card')) return;
      isDragging = true;
      hasMoved = false;
      dragStart.x = e.clientX;
      dragStart.y = e.clientY;
      panStart.x = topoPan.x;
      panStart.y = topoPan.y;
      curContainer.style.cursor = 'grabbing';
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - dragStart.x;
      const dy = e.clientY - dragStart.y;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) hasMoved = true;
      topoPan.x = panStart.x + dx;
      topoPan.y = panStart.y + dy;
      applyTopoTransform(curCanvas);
    });

    document.addEventListener('mouseup', () => {
      if (isDragging) {
        isDragging = false;
        curContainer.style.cursor = '';
      }
    });

    // 鼠标滚轮缩放
    curContainer.addEventListener('wheel', (e) => {
      if (e.target.closest('.topo-node-card')) return;
      e.preventDefault();
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      applyTopoScale(Math.max(0.5, Math.min(2, topoScale + delta)));
      applyTopoTransform(curCanvas);
    }, { passive: false });
  }

  function applyTopoTransform(canvas) {
    if (!canvas) return;
    canvas.style.transform = `translate(${topoPan.x}px, ${topoPan.y}px) scale(${topoScale})`;
  }

  // 渲染设备卡片
  function renderDeviceCard(device, x, y, w, h) {
    const isInternet = device.isInternet;
    const isLocal = device.type === '本机';
    const isGateway = device.type?.includes('路由') || device.type?.includes('网关');
    const isOnline = device.status === '在线';

    // 卡片颜色
    let bgColor, borderColor, textColor, iconBg, iconColor;
    if (isInternet) {
      bgColor = 'var(--scanner-ink)';
      borderColor = 'var(--scanner-ink)';
      textColor = '#fff';
      iconBg = 'rgba(255,255,255,0.15)';
      iconColor = '#fff';
    } else {
      bgColor = 'var(--scanner-card)';
      borderColor = 'var(--scanner-border)';
      textColor = 'var(--scanner-ink)';
      iconBg = 'var(--scanner-muted)';
      iconColor = 'var(--scanner-primary)';
    }

    // 类型徽章
    const typeLabel = isInternet ? 'WAN' : (device.type || '未知');
    const badgeColor = isLocal ? 'var(--scanner-primary)' :
                       isGateway ? 'var(--scanner-state-info)' :
                       isOnline ? 'var(--scanner-state-success)' :
                       'var(--scanner-state-warning)';
    const badgeTextColor = isLocal ? '#fff' :
                           isGateway ? '#fff' :
                           isOnline ? '#fff' : '#fff';

    // 图标
    let iconName;
    if (isInternet) iconName = 'cloud';
    else if (isGateway) iconName = 'router';
    else if (device.type?.includes('手机')) iconName = 'smartphone';
    else if (device.type?.includes('电脑') || isLocal) iconName = 'monitor';
    else if (device.type?.includes('IoT')) iconName = 'cpu';
    else iconName = 'box';

    // 属性徽章
    const badges = [];
    if (isGateway) badges.push('路由器');
    if (device.isPrivate) badges.push('私有地址');
    if (device.manufacturer) badges.push(device.manufacturer);

    // 状态行
    const statusDotColor = isOnline ? 'var(--scanner-state-success)' : 'var(--scanner-state-warning)';
    const statusText = isOnline ? '在线' : (device.status || '未知');
    const latencyText = device.latency != null && device.latency >= 0 ? `${device.latency.toFixed(1)} ms` : '';

    const badgesHtml = badges.length > 0
      ? badges.map(b => `<span style="font-size:9px; padding:1px 5px; border-radius:3px; background:var(--scanner-muted); color:var(--scanner-ink-2);">${b}</span>`).join(' ')
      : '';

    const macHtml = device.mac
      ? `<span style="font-size:10px; color:var(--scanner-ink-3); font-family:var(--scanner-font-mono);">MAC ${device.mac}</span>`
      : '';

    const statusHtml = isInternet ? '' : `
      <div style="display:flex; align-items:center; gap:6px; font-size:10px;">
        <span style="display:inline-flex; align-items:center; gap:3px;">
          <span style="width:5px; height:5px; border-radius:50%; background:${statusDotColor}; display:inline-block;"></span>
          <span style="color:${statusDotColor};">${statusText}</span>
        </span>
        ${latencyText ? `<span style="color:var(--scanner-ink-3);">· ${latencyText}</span>` : ''}
      </div>
    `;

    return `
      <div class="topo-node-card" data-topo-ip="${device.ip || ''}" style="position:absolute; left:${x}px; top:${y}px; width:${w}px; height:${h}px; background:${bgColor}; border:1px solid ${borderColor}; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.08); overflow:hidden; cursor:pointer; transition: box-shadow 0.2s; user-select:none;" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,0.12)'" onmouseout="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">
        <div style="padding:10px 12px;">
          <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
            <span style="font-size:12px; font-weight:600; font-family:var(--scanner-font-mono); color:${textColor};">${device.ip || '?'}</span>
            <span style="font-size:9px; padding:2px 6px; border-radius:4px; background:${badgeColor}; color:${badgeTextColor}; font-weight:500;">${typeLabel}</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:${isInternet ? '0' : '4px'};">
            <div style="width:26px; height:26px; border-radius:6px; background:${iconBg}; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
              <i data-lucide="${iconName}" style="width:14px; height:14px; color:${iconColor};"></i>
            </div>
            <div style="flex:1; min-width:0;">
              <div style="font-size:11px; color:${textColor}; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${device.hostname || device.type || '未知设备'}</div>
              ${badgesHtml ? `<div style="display:flex; gap:3px; margin-top:2px; flex-wrap:wrap;">${badgesHtml}</div>` : ''}
            </div>
          </div>
          ${isInternet ? '' : `
            <div style="display:flex; flex-direction:column; gap:2px; margin-top:6px; padding-top:6px; border-top:1px solid ${borderColor};">
              ${macHtml}
              ${statusHtml}
            </div>
          `}
        </div>
      </div>
    `;
  }

  // 渲染连线（基于真实父子关系）
  function renderEdges(svg, positions, layers, canvasWidth, canvasHeight, hasGateway, terminalGroups, intermediateDevices) {
    if (!svg) return;
    svg.setAttribute('width', canvasWidth);
    svg.setAttribute('height', canvasHeight);
    svg.setAttribute('viewBox', `0 0 ${canvasWidth} ${canvasHeight}`);

    const parts = [];
    const nodeHeight = 90;

    // 辅助：画一条贝塞尔曲线
    function drawEdge(srcPos, dstPos, isDashed, color, opacity) {
      const x1 = srcPos.x;
      const y1 = srcPos.top + nodeHeight;
      const x2 = dstPos.x;
      const y2 = dstPos.top;
      const midY = (y1 + y2) / 2;
      const d = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;
      parts.push(`<path d="${d}" fill="none" stroke="${color}" stroke-width="1.5" stroke-dasharray="${isDashed ? '5 4' : '0'}" opacity="${opacity}"/>`);
    }

    function getPos(device) {
      if (!device) return null;
      const key = device.isInternet ? 'internet' : (device.ip || '');
      return positions[key] || null;
    }

    // 1. Internet → 网关（虚线）
    if (hasGateway) {
      const internetPos = positions['internet'];
      const gatewayPos = getPos(layers[1] && layers[1][0]);
      if (internetPos && gatewayPos) {
        drawEdge(internetPos, gatewayPos, true, 'var(--scanner-ink-3)', 0.5);
      }
    }

    // 2. 网关 → 中间设备（如果有中间设备层）
    if (intermediateDevices && intermediateDevices.length > 0 && hasGateway) {
      const gatewayDevice = layers[1] && layers[1][0];
      const gatewayPos = getPos(gatewayDevice);
      for (const infra of intermediateDevices) {
        const infraPos = getPos(infra);
        if (gatewayPos && infraPos) {
          drawEdge(gatewayPos, infraPos, false, 'var(--scanner-primary)', 0.4);
        }
      }
    }

    // 3. 基于真实父子关系连线：parent → children
    if (terminalGroups) {
      for (const group of terminalGroups) {
        const parentPos = getPos(group.parent);
        if (!parentPos) continue;
        for (const child of group.children) {
          if (child === group.parent) continue;
          const childPos = getPos(child);
          if (!childPos) continue;
          // 中间设备的下级用 info 色，网关直连用 primary 色
          const isInfraChild = intermediateDevices && intermediateDevices.includes(group.parent);
          const color = isInfraChild ? 'var(--scanner-state-info)' : 'var(--scanner-primary)';
          drawEdge(parentPos, childPos, false, color, 0.4);
        }
      }
    } else {
      // 兜底：相邻层连线（无分组信息时）
      for (let i = 0; i < layers.length - 1; i++) {
        for (const src of layers[i]) {
          const srcPos = getPos(src);
          if (!srcPos) continue;
          for (const dst of layers[i + 1]) {
            const dstPos = getPos(dst);
            if (!dstPos) continue;
            const isDashed = src.isInternet;
            drawEdge(srcPos, dstPos, isDashed, isDashed ? 'var(--scanner-ink-3)' : 'var(--scanner-primary)', isDashed ? 0.5 : 0.4);
          }
        }
      }
    }

    svg.innerHTML = parts.join('');
  }

  // 缩放
  function applyTopoScale(scale) {
    topoScale = Math.max(0.5, Math.min(2, scale));
    const canvas = document.getElementById('topology-canvas');
    if (canvas) {
      applyTopoTransform(canvas);
    }
  }

  function clearDevices() {
    devices = [];
    renderDevices();
    renderTopology();
    setText(els.scanFound, '0');
    setText(els.statDevices, '0');
    setText(els.statOnline, '0');
    setText(els.statLatency, '0.0');
    setText(els.statTime, '0');
    setText(els.statFingerprints, '0');
    setText(els.statEvidence, '0');
    setText(els.scanElapsed, '0');
    els.scanProgress.style.width = '0%';
  }

  function updateStats() {
    const online = devices.filter(d => d.status === '在线').length;
    const latencies = devices.filter(d => d.latency != null).map(d => d.latency);
    const avg = latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : '0.0';
    const withServices = devices.filter(d => d.services && d.services.length > 0).length;
    const pending = devices.filter(d => !d.mac).length;

    setText(els.statDevices, devices.length.toString());
    setText(els.statOnline, online.toString());
    setText(els.statLatency, avg);
    setText(els.statFingerprints, withServices.toString());
    setText(els.statEvidence, pending.toString());
  }

  function addOrUpdateDevice(device) {
    const existing = devices.find(d => d.ip === device.ip);
    if (existing) {
      Object.assign(existing, device);
    } else {
      devices.push(device);
    }
    updateStats();
    renderDevices();
  }

  function setScanning(scanning) {
    isScanning = scanning;
    const scanLoading = document.getElementById('scan-loading');
    const scanLoadingPct = document.getElementById('scan-loading-pct');
    const scanLoadingDetail = document.getElementById('scan-loading-detail');

    if (scanning) {
      els.btnStart.style.display = 'none';
      els.btnStop.style.display = 'inline-flex';
      // 禁用模式选择按钮
      document.querySelectorAll('.mode-btn').forEach(b => b.classList.add('btn-disabled'));
      // 显示扫描动画
      if (scanLoading) {
        scanLoading.style.display = 'block';
        scanLoading.classList.remove('hidden');
      }
      if (scanLoadingPct) scanLoadingPct.textContent = '0%';
      if (scanLoadingDetail) scanLoadingDetail.textContent = '准备扫描...';
    } else {
      els.btnStart.style.display = 'inline-flex';
      els.btnStop.style.display = 'none';
      // 恢复模式选择按钮
      document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('btn-disabled'));
      // 隐藏扫描动画
      if (scanLoading) {
        scanLoading.style.display = 'none';
        scanLoading.classList.add('hidden');
      }
      if (scanTimer) {
        clearInterval(scanTimer);
        scanTimer = null;
      }
    }
  }

  async function startScan() {
    if (isScanning) return;
    clearDevices();
    setScanning(true);
    scanStartTime = Date.now();

    scanTimer = setInterval(() => {
      setText(els.scanElapsed, ((Date.now() - scanStartTime) / 1000).toFixed(1));
    }, 200);

    const config = modeConfig[currentMode];
    const cidr = selectedAdapter ? selectedAdapter.cidr : els.scanTarget.value.replace(/.*?(\d+\.\d+\.\d+\.\d+\/\d+).*/, '$1');

    try {
      scanPromise = api.scanNetwork({ cidr, concurrency: config.concurrency, timeout: config.timeout });
      const result = await scanPromise;
      if (result.success) {
        // 扫描完成后一次性显示所有在线设备
        devices = result.devices;
        updateStats();
        renderDevices();
        renderTopology();
        setText(els.scanFound, devices.length.toString());
        setText(els.statTime, (result.elapsed / 1000).toFixed(1));
        // 安全告警检测 + 历史记录保存
        activeAlerts = detectAlerts(devices);
        updateAlertBadge();
        saveScanHistory(cidr, devices, result.elapsed);
      } else {
        alert(`扫描失败: ${result.error}`);
      }
    } catch (err) {
      console.error('Scan error:', err);
      alert(`扫描异常: ${err.message}`);
    } finally {
      setScanning(false);
      setText(els.scanElapsed, ((Date.now() - scanStartTime) / 1000).toFixed(1));
    }
  }

  async function stopScan() {
    if (!isScanning) return;
    await api.stopScan();
  }

  async function exportResult() {
    if (devices.length === 0) {
      showToast('暂无数据，请先执行扫描');
      return;
    }

    // 显示格式选择弹窗
    const overlay = document.getElementById('export-modal-overlay');
    const closeBtn = document.getElementById('export-modal-close');
    const formatBtns = overlay.querySelectorAll('.export-format-btn');

    overlay.style.display = 'flex';
    lucide.createIcons();

    const chosen = await new Promise(resolve => {
      const cleanup = () => {
        closeBtn.removeEventListener('click', onCancel);
        overlay.removeEventListener('click', onOverlayClick);
        formatBtns.forEach(btn => btn.removeEventListener('click', onSelect));
      };
      const onCancel = () => { cleanup(); resolve(null); };
      const onOverlayClick = (e) => { if (e.target === overlay) { cleanup(); resolve(null); } };
      const onSelect = (e) => {
        cleanup();
        const btn = e.currentTarget;
        resolve(btn.dataset.format);
      };

      closeBtn.addEventListener('click', onCancel);
      overlay.addEventListener('click', onOverlayClick);
      formatBtns.forEach(btn => btn.addEventListener('click', onSelect));
    });

    overlay.style.display = 'none';

    if (!chosen) return; // 用户取消

    const result = await api.exportResult({
      format: chosen,
      cidr: selectedAdapter?.cidr || '',
      devices,
      elapsed: Date.now() - scanStartTime
    });
    if (result.success) {
      showToast(`报告已导出 (${chosen.toUpperCase()})`);
    } else if (!result.canceled) {
      showToast(`导出失败: ${result.error}`);
    }
  }

  function showDeviceDetail(device) {
    const overlay = document.getElementById('device-detail-overlay');
    const drawer = document.getElementById('device-detail-drawer');
    const titleEl = document.getElementById('detail-title');
    const subtitleEl = document.getElementById('detail-subtitle');
    const iconWrap = document.getElementById('detail-icon-wrap');
    const ipHero = document.getElementById('detail-ip-hero');
    const ipValue = document.getElementById('detail-ip-value');
    const ipMeta = document.getElementById('detail-ip-meta');
    const body = document.getElementById('detail-body');

    currentDetailDevice = device;

    const icon = getDeviceIcon(device);
    const isLocal = device.type === '本机';
    const hostname = device.hostname || (isLocal ? (localInfo?.hostname || '本机') : '-');
    const methodLabel = device.method === 'icmp' ? 'ICMP' : device.method === 'tcp' ? 'TCP' : device.method || '-';
    const oui = device.mac ? device.mac.slice(0, 8).toUpperCase() : '-';

    titleEl.textContent = device.hostname || (isLocal ? (localInfo?.hostname || '本机') : device.type || '设备详情');
    subtitleEl.textContent = `${device.type || '未知'} · ${device.ip}`;

    iconWrap.innerHTML = `<i data-lucide="${icon}" style="width:20px; height:20px;"></i>`;
    if (isLocal) {
      iconWrap.style.background = 'var(--scanner-primary)';
      iconWrap.style.color = 'var(--scanner-primary-foreground)';
    } else {
      iconWrap.style.background = 'var(--scanner-state-info-bg)';
      iconWrap.style.color = 'var(--scanner-state-info)';
    }

    ipValue.textContent = device.ip;
    ipMeta.textContent = `在线 · ${methodLabel}${device.latency != null ? ' · ' + device.latency + 'ms' : ''}`;

    const categoryLabel = { phone: '手机', computer: '电脑', router: '路由器/网关', iot: 'IoT 设备', camera: '摄像头', virtual: '虚拟网卡', unknown: '未知' }[device.category] || '未知';

    const rows = [
      { label: 'IP 地址', value: device.ip, mono: true },
      { label: 'MAC 地址', value: device.mac ? device.mac.toUpperCase() : '未知', mono: true },
      { label: '厂商 / OUI', value: device.type || '-', sub: oui },
      { label: '主机名', value: hostname },
      { label: '设备类型', value: device.type || '未知' },
      { label: '设备分类', value: categoryLabel },
      { label: '所属网段', value: selectedAdapter?.cidr || '-', mono: true },
      { label: '探测方式', value: methodLabel },
      { label: '延迟', value: device.latency != null ? `${device.latency} ms` : '-', mono: true }
    ];

    body.innerHTML = rows.map(row => {
      let valHtml;
      if (row.badge) {
        valHtml = `<span style="display:inline-flex; align-items:center; gap:4px; font-size:11px; font-weight:500; padding:2px 8px; border-radius:999px; background:var(--scanner-state-success-bg); color:var(--scanner-state-success);"><span style="width:6px; height:6px; border-radius:50%; background:currentColor;"></span>${row.value}</span>`;
      } else {
        const cls = row.mono ? 'scanner-mono' : '';
        valHtml = `<div><span class="${cls}">${row.value}</span>${row.sub ? `<div class="sub">${row.sub}</div>` : ''}</div>`;
      }
      return `
        <div class="drawer-row">
          <span class="label">${row.label}</span>
          <div class="value">${valHtml}</div>
        </div>
      `;
    }).join('');

    // 显示该设备的告警信息
    const deviceAlerts = activeAlerts.filter(a => a.ip === device.ip);
    if (deviceAlerts.length > 0) {
      const alertHtml = deviceAlerts.map(a => {
        const cls = a.level === 'high' ? 'high' : 'med';
        const icon = a.level === 'high' ? 'alert-triangle' : 'alert-circle';
        return `<span class="alert-chip ${cls}"><i data-lucide="${icon}" style="width:11px; height:11px;"></i>${a.title}</span>`;
      }).join('');
      body.insertAdjacentHTML('beforeend', `
        <div class="drawer-row" style="flex-direction:column; align-items:flex-start; gap:6px;">
          <span class="label">安全告警</span>
          <div style="text-align:left; width:100%;">${alertHtml}</div>
        </div>
      `);
    }

    // 端口扫描结果
    const svcs = device.services || [];
    if (svcs.length > 0) {
      const riskColors = { high: 'var(--scanner-state-error)', medium: 'var(--scanner-state-warning)', low: 'var(--scanner-state-success)' };
      const riskBg = { high: 'var(--scanner-state-error-bg)', medium: 'var(--scanner-state-warning-bg)', low: 'var(--scanner-state-success-bg)' };
      const portListHtml = svcs.map(s => {
        const rc = riskColors[s.risk] || riskColors.low;
        const rb = riskBg[s.risk] || riskBg.low;
        return `
          <div style="display:flex; align-items:flex-start; gap:10px; padding:10px 0; border-bottom:1px solid var(--scanner-border);">
            <div style="display:flex; flex-direction:column; align-items:center; gap:2px; min-width:48px;">
              <span class="scanner-mono" style="font-size:14px; font-weight:700; color:var(--scanner-ink);">${s.port}</span>
              <span style="font-size:9px; padding:1px 5px; border-radius:3px; background:${rb}; color:${rc}; font-weight:500;">${s.risk === 'high' ? '高危' : s.risk === 'medium' ? '中危' : '低危'}</span>
            </div>
            <div style="flex:1; min-width:0;">
              <div style="font-size:12px; font-weight:600; color:var(--scanner-ink); margin-bottom:2px;">${s.name}</div>
              <div style="font-size:11px; color:var(--scanner-ink-2);">${s.desc || ''}</div>
            </div>
          </div>
        `;
      }).join('');
      body.insertAdjacentHTML('beforeend', `
        <div style="margin-top:16px;">
          <div style="font-size:12px; font-weight:600; color:var(--scanner-ink-2); margin-bottom:4px;">开放端口 (${svcs.length})</div>
          ${portListHtml}
        </div>
      `);
    } else {
      body.insertAdjacentHTML('beforeend', `
        <div style="margin-top:16px; padding:12px; border-radius:8px; background:var(--scanner-muted); text-align:center;">
          <span style="font-size:12px; color:var(--scanner-ink-3);">未发现开放端口</span>
        </div>
      `);
    }

    // 重置操作面板
    resetActionPanels();

    // 显示 overlay 并触发动画
    overlay.style.display = 'flex';
    // 短暂延迟让 CSS transition 生效
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        drawer.style.transform = 'translateX(0)';
      });
    });
    lucide.createIcons();
  }

  function resetActionPanels() {
    const pingResult = document.getElementById('ping-result');
    const portscanResult = document.getElementById('portscan-result');
    if (pingResult) pingResult.innerHTML = '<div class="port-empty">点击"开始 Ping"进行连通性测试</div>';
    if (portscanResult) portscanResult.innerHTML = '<div class="port-empty">点击"扫描常用端口"开始检测</div>';
  }

  function hideDeviceDetail() {
    const overlay = document.getElementById('device-detail-overlay');
    const drawer = document.getElementById('device-detail-drawer');
    drawer.style.transform = 'translateX(100%)';
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 260);
  }

  // ── 右键上下文菜单 ──────────────────────────────
  function showContextMenu(device, x, y) {
    const menu = document.getElementById('ctx-menu');
    const isLocal = device.type === '本机';
    const items = [
      { icon: 'activity', label: 'Ping 测试（5 次）', action: () => { showDeviceDetail(device); runPingTest(device); } },
      { icon: 'git-branch', label: '端口扫描', action: () => { showDeviceDetail(device); runPortScan(device, 'common'); } },
      { icon: 'radio', label: '连续监控', action: () => startMonitor(device) },
      { divider: true },
      { icon: 'copy', label: '复制 IP 地址', action: () => copyToClipboard(device.ip) },
      { icon: 'copy', label: '复制 MAC 地址', action: () => copyToClipboard(device.mac || '') },
      { divider: true },
      { icon: 'external-link', label: '查看详情', action: () => showDeviceDetail(device) }
    ];
    if (isLocal) {
      // 本机不支持连续监控
      items.splice(2, 1);
    }
    menu.innerHTML = items.map(it => {
      if (it.divider) return '<div class="ctx-menu-divider"></div>';
      return `<button class="ctx-menu-item" data-action="${it.label}"><i data-lucide="${it.icon}"></i>${it.label}</button>`;
    }).join('');
    menu.style.display = 'block';
    // 定位（避免溢出窗口）
    const rect = menu.getBoundingClientRect();
    let left = x, top = y;
    if (left + rect.width > window.innerWidth) left = window.innerWidth - rect.width - 8;
    if (top + rect.height > window.innerHeight) top = window.innerHeight - rect.height - 8;
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
    lucide.createIcons();

    // 绑定点击
    menu.querySelectorAll('.ctx-menu-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const label = btn.dataset.action;
        const item = items.find(i => i.label === label);
        hideContextMenu();
        if (item && item.action) item.action();
      });
    });
  }

  function hideContextMenu() {
    const menu = document.getElementById('ctx-menu');
    if (menu) menu.style.display = 'none';
  }

  function copyToClipboard(text) {
    if (!text) { showToast('内容为空，无法复制'); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => showToast(`已复制: ${text}`),
        () => fallbackCopy(text)
      );
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showToast(`已复制: ${text}`); }
    catch { showToast('复制失败'); }
    document.body.removeChild(ta);
  }

  function showToast(msg) {
    let toast = document.getElementById('scanner-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'scanner-toast';
      toast.style.cssText = 'position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:var(--scanner-ink); color:#fff; padding:10px 20px; border-radius:8px; font-size:13px; z-index:200; box-shadow:var(--scanner-shadow-3); opacity:0; transition:opacity 0.2s;';
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.opacity = '1';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 2000);
  }

  // ── Ping 连通性测试 ──────────────────────────────
  async function runPingTest(device) {
    const resultEl = document.getElementById('ping-result');
    const runBtn = document.getElementById('ping-run-btn');
    if (!resultEl || !device) return;
    runBtn.disabled = true;
    resultEl.innerHTML = '<div class="port-empty">正在测试...</div>';

    const results = [];
    for (let i = 0; i < 5; i++) {
      try {
        const r = await api.pingHost(device.ip, 2000);
        results.push({ seq: i + 1, alive: !!r.alive, latency: r.latency });
      } catch {
        results.push({ seq: i + 1, alive: false, latency: null });
      }
      // 实时渲染进度
      renderPingResult(resultEl, results, true);
    }
    renderPingResult(resultEl, results, false);
    runBtn.disabled = false;
  }

  function renderPingResult(el, results, pending) {
    const okCount = results.filter(r => r.alive).length;
    const latencies = results.filter(r => r.alive && r.latency != null).map(r => r.latency);
    const avg = latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(1) : '-';
    const loss = results.length ? (((results.length - okCount) / results.length) * 100).toFixed(0) : '0';
    // 抖动：相邻延迟差值的平均
    let jitter = '-';
    if (latencies.length >= 2) {
      let sum = 0;
      for (let i = 1; i < latencies.length; i++) sum += Math.abs(latencies[i] - latencies[i - 1]);
      jitter = (sum / (latencies.length - 1)).toFixed(1);
    }
    const grid = results.map(r => {
      const cls = r.alive ? 'ok' : 'fail';
      const val = r.alive ? (r.latency != null ? r.latency + 'ms' : 'OK') : '超时';
      return `<div class="ping-cell ${cls}"><span class="seq">#${r.seq}</span>${val}</div>`;
    }).join('');
    const pendingHint = pending ? `<div class="action-panel-hint" style="margin-top:8px;">测试进行中... 已完成 ${results.length}/5</div>` : '';
    el.innerHTML = `
      <div class="ping-grid">${grid}</div>
      <div class="ping-summary" style="margin-top:8px;">
        <span>成功 <b>${okCount}/${results.length}</b></span>
        <span>丢包率 <b>${loss}%</b></span>
        <span>平均 <b>${avg} ms</b></span>
        <span>抖动 <b>${jitter} ms</b></span>
      </div>
      ${pendingHint}
    `;
  }

  // ── 端口扫描 ──────────────────────────────────
  async function runPortScan(device, mode) {
    const resultEl = document.getElementById('portscan-result');
    const runBtn = document.getElementById('portscan-run-btn');
    const fullBtn = document.getElementById('portscan-full-btn');
    if (!resultEl || !device) return;
    runBtn.disabled = true;
    fullBtn.disabled = true;
    resultEl.innerHTML = '<div class="port-empty"><div class="action-panel-hint" style="margin-bottom:6px;">正在扫描端口，请稍候...</div></div>';

    let ports;
    if (mode === 'full') {
      ports = [];
      for (let p = 1; p <= 1024; p++) ports.push(p);
    } else {
      ports = Object.keys(PORT_SERVICES).map(Number);
    }

    try {
      const r = await api.scanPorts(device.ip, ports);
      if (r.success) {
        renderPortScanResult(resultEl, r.openPorts || []);
      } else {
        resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-error);">扫描失败: ${r.error || '未知错误'}</div>`;
      }
    } catch (err) {
      resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-error);">扫描异常: ${err.message}</div>`;
    } finally {
      runBtn.disabled = false;
      fullBtn.disabled = false;
    }
  }

  function renderPortScanResult(el, openPorts) {
    if (!openPorts.length) {
      el.innerHTML = '<div class="port-empty">未发现开放端口</div>';
      return;
    }
    const items = openPorts.map(item => {
      const port = typeof item === 'object' ? item.port : item;
      const svcName = typeof item === 'object' ? item.name : (PORT_SERVICES[port] || '未知');
      const svcDesc = typeof item === 'object' ? (item.desc || '') : (PORT_DESCRIPTIONS[port] || '');
      const riskLevel = typeof item === 'object' ? item.risk : (HIGH_RISK_PORTS.includes(port) ? 'high' : MED_RISK_PORTS.includes(port) ? 'medium' : '');
      const riskLabel = riskLevel === 'high' ? '高危' : riskLevel === 'medium' ? '中危' : '低危';
      const riskCls = riskLevel === 'high' ? 'high' : riskLevel === 'medium' ? 'med' : '';
      let risk = riskCls ? `<span class="port-risk ${riskCls}">${riskLabel}</span>` : '';
      return `
        <div class="port-item" style="flex-direction:column; align-items:flex-start; gap:4px; padding:10px 8px;">
          <div style="display:flex; align-items:center; gap:8px; width:100%;">
            <span class="port-num">${port}</span>
            <span class="port-svc">${svcName}</span>
            ${risk}
          </div>
          ${svcDesc ? `<div style="font-size:11px; color:var(--scanner-ink-3); padding-left:2px;">${svcDesc}</div>` : ''}
        </div>
      `;
    }).join('');
    el.innerHTML = `<div class="port-list">${items}</div><div class="action-panel-hint" style="margin-top:6px;">共发现 ${openPorts.length} 个开放端口</div>`;
  }

  // ── 连续监控 ──────────────────────────────────
  function startMonitor(device) {
    stopMonitor();
    const float = document.getElementById('monitor-float');
    if (!float || !device) return;
    monitorStats = { success: 0, total: 0, latencies: [], history: [] };
    document.getElementById('monitor-ip').textContent = device.ip;
    renderMonitor();
    float.style.display = 'block';
    lucide.createIcons();

    const tick = async () => {
      try {
        const r = await api.pingHost(device.ip, 2000);
        monitorStats.total++;
        if (r.alive) {
          monitorStats.success++;
          monitorStats.latencies.push(r.latency || 0);
          monitorStats.history.push({ alive: true, latency: r.latency });
        } else {
          monitorStats.history.push({ alive: false, latency: null });
        }
      } catch {
        monitorStats.total++;
        monitorStats.history.push({ alive: false, latency: null });
      }
      // 保留最近 30 个点
      if (monitorStats.history.length > 30) monitorStats.history.shift();
      if (monitorStats.latencies.length > 30) monitorStats.latencies.shift();
      renderMonitor();
    };
    tick();
    monitorTimer = setInterval(tick, 3000);
  }

  function stopMonitor() {
    if (monitorTimer) { clearInterval(monitorTimer); monitorTimer = null; }
    const float = document.getElementById('monitor-float');
    if (float) float.style.display = 'none';
  }

  function renderMonitor() {
    const last = monitorStats.history[monitorStats.history.length - 1];
    const statusEl = document.getElementById('monitor-status');
    const latencyEl = document.getElementById('monitor-latency');
    if (last && last.alive) {
      statusEl.innerHTML = `<span class="w-2 h-2 rounded-full" style="background:var(--scanner-state-success);"></span><span style="color:var(--scanner-state-success); font-weight:600;">在线</span><span style="color:var(--scanner-ink-3);">·</span><span style="color:var(--scanner-ink-2); font-family:var(--scanner-font-mono);" id="monitor-latency">${last.latency != null ? last.latency : 0} ms</span>`;
    } else {
      statusEl.innerHTML = `<span class="w-2 h-2 rounded-full" style="background:var(--scanner-state-error);"></span><span style="color:var(--scanner-state-error); font-weight:600;">离线</span><span style="color:var(--scanner-ink-3);">·</span><span style="color:var(--scanner-ink-2);" id="monitor-latency">超时</span>`;
    }
    document.getElementById('monitor-success').textContent = monitorStats.success;
    document.getElementById('monitor-total').textContent = monitorStats.total;
    const avg = monitorStats.latencies.length ? (monitorStats.latencies.reduce((a, b) => a + b, 0) / monitorStats.latencies.length).toFixed(0) : '-';
    document.getElementById('monitor-avg').textContent = avg === '-' ? '-' : avg + 'ms';
    const loss = monitorStats.total ? (((monitorStats.total - monitorStats.success) / monitorStats.total) * 100).toFixed(0) : '0';
    document.getElementById('monitor-loss').textContent = loss + '%';
    // 图表
    const chart = document.getElementById('monitor-chart');
    const maxLat = Math.max(...monitorStats.latencies, 1);
    chart.innerHTML = monitorStats.history.map(h => {
      if (!h.alive) return '<div class="bar fail" style="height:100%;"></div>';
      const heightPct = Math.max(8, (h.latency / maxLat) * 100);
      return `<div class="bar" style="height:${heightPct}%;"></div>`;
    }).join('');
  }

  // ── 告警检测 ──────────────────────────────────
  function detectAlerts(devs) {
    const alerts = [];
    const baseline = loadBaseline();
    const knownMacs = new Set(baseline.map(b => b.mac).filter(Boolean));

    for (const d of devs) {
      // 1. 可疑设备：MAC 缺失
      if (!d.mac || d.mac === '00:00:00:00:00:00') {
        alerts.push({ ip: d.ip, level: 'med', title: 'MAC 地址缺失', type: 'suspect' });
      }
      // 2. 可疑设备：未知类型/厂商
      if (d.type === '在线设备' || !d.type) {
        alerts.push({ ip: d.ip, level: 'med', title: '设备类型未知', type: 'suspect' });
      }
      // 3. 高危端口
      if (d.services && Array.isArray(d.services)) {
        for (const svc of d.services) {
          if (svc && typeof svc === 'object' && svc.risk === 'high') {
            alerts.push({ ip: d.ip, level: 'high', title: `高危端口开放: ${svc.port} (${svc.name})`, type: 'port' });
          }
        }
      }
      // 4. 未授权设备：不在基线白名单中（仅当基线存在时检测）
      if (baseline.length > 0 && d.mac && !knownMacs.has(d.mac) && d.type !== '本机') {
        alerts.push({ ip: d.ip, level: 'high', title: '未授权设备（不在基线中）', type: 'unauthorized' });
      }
    }
    return alerts;
  }

  function updateAlertBadge() {
    const badge = document.getElementById('alert-count-badge');
    if (!badge) return;
    const highCount = activeAlerts.filter(a => a.level === 'high').length;
    if (activeAlerts.length > 0) {
      badge.style.display = 'flex';
      badge.textContent = activeAlerts.length;
      badge.style.background = highCount > 0 ? 'var(--scanner-state-error)' : 'var(--scanner-state-warning)';
    } else {
      badge.style.display = 'none';
    }
  }

  function showAlertsPanel() {
    if (activeAlerts.length === 0) {
      showToast('当前无安全告警');
      return;
    }
    // 复用历史面板结构显示告警
    const panel = document.getElementById('history-panel');
    const list = document.getElementById('history-list');
    const header = panel.querySelector('.history-panel-header h3');
    header.textContent = `安全告警 (${activeAlerts.length})`;
    list.innerHTML = activeAlerts.map(a => {
      const cls = a.level === 'high' ? 'high' : 'med';
      const color = a.level === 'high' ? 'var(--scanner-state-error)' : 'var(--scanner-state-warning)';
      return `
        <div class="history-item" style="border-left:3px solid ${color};">
          <div class="history-item-top">
            <span class="history-item-time scanner-mono">${a.ip}</span>
            <span class="alert-chip ${cls}">${a.level === 'high' ? '高危' : '中危'}</span>
          </div>
          <div class="history-item-meta">${a.title}</div>
          <div class="history-item-sub">类型: ${a.type}</div>
        </div>
      `;
    }).join('');
    panel.style.display = 'flex';
    lucide.createIcons();
  }

  // ── 扫描历史记录（localStorage） ──────────────────
  function saveScanHistory(cidr, devs, elapsed) {
    try {
      const history = loadHistory();
      const deviceSummary = devs.map(d => ({
        ip: d.ip,
        mac: d.mac || null,
        hostname: d.hostname || null,
        type: d.type || null,
        status: d.status || null,
        latency: d.latency != null ? d.latency : null,
        services: d.services || []
      }));
      history.unshift({
        id: Date.now(),
        time: Date.now(),
        cidr: cidr || '',
        elapsed: elapsed || 0,
        deviceCount: devs.length,
        onlineCount: devs.filter(d => d.status === '在线').length,
        devices: deviceSummary
      });
      if (history.length > HISTORY_MAX) history.length = HISTORY_MAX;
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
      // 首次扫描建立基线
      const baseline = loadBaseline();
      if (baseline.length === 0 && devs.length > 0) {
        const newBaseline = devs.filter(d => d.mac).map(d => ({ ip: d.ip, mac: d.mac, type: d.type }));
        localStorage.setItem(BASELINE_KEY, JSON.stringify(newBaseline));
      }
    } catch (e) {
      console.warn('保存历史失败:', e);
    }
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function loadBaseline() {
    try {
      const raw = localStorage.getItem(BASELINE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  function showHistoryPanel() {
    const panel = document.getElementById('history-panel');
    const list = document.getElementById('history-list');
    const header = panel.querySelector('.history-panel-header h3');
    header.textContent = '扫描历史记录';
    const history = loadHistory();
    if (history.length === 0) {
      list.innerHTML = '<div class="history-empty">暂无扫描历史<br><span style="font-size:11px;">完成一次扫描后会自动保存</span></div>';
    } else {
      list.innerHTML = history.map(h => {
        const d = new Date(h.time);
        const timeStr = `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
        const elapsedStr = h.elapsed ? (h.elapsed / 1000).toFixed(1) + 's' : '-';
        return `
          <div class="history-item" data-history-id="${h.id}">
            <div class="history-item-top">
              <span class="history-item-time">${timeStr}</span>
              <span class="history-item-meta">${h.onlineCount}/${h.deviceCount} 在线 · ${elapsedStr}</span>
            </div>
            <div class="history-item-sub">${h.cidr} · ${h.deviceCount} 台设备</div>
          </div>
        `;
      }).join('');
      // 绑定点击查看详情
      list.querySelectorAll('.history-item').forEach(item => {
        item.addEventListener('click', () => {
          const id = parseInt(item.dataset.historyId, 10);
          const rec = history.find(h => h.id === id);
          if (rec) showHistoryDetail(rec);
        });
      });
    }
    panel.style.display = 'flex';
    lucide.createIcons();
  }

  function showHistoryDetail(rec) {
    const panel = document.getElementById('history-panel');
    const list = document.getElementById('history-list');
    const header = panel.querySelector('.history-panel-header h3');
    const d = new Date(rec.time);
    const timeStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    header.textContent = '历史详情';
    list.innerHTML = `
      <div style="padding:12px 14px; border-bottom:1px solid var(--scanner-border);">
        <div style="font-size:13px; font-weight:600; color:var(--scanner-ink); margin-bottom:6px;">${timeStr}</div>
        <div style="font-size:11px; color:var(--scanner-ink-2); display:flex; gap:12px; flex-wrap:wrap;">
          <span>网段 <b class="scanner-mono">${rec.cidr}</b></span>
          <span>设备 <b>${rec.deviceCount}</b></span>
          <span>在线 <b style="color:var(--scanner-state-success);">${rec.onlineCount}</b></span>
          <span>耗时 <b>${(rec.elapsed / 1000).toFixed(1)}s</b></span>
        </div>
      </div>
      <div style="padding:8px;">
        ${(rec.devices || []).map(dev => {
          const statusColor = dev.status === '在线' ? 'var(--scanner-state-success)' : 'var(--scanner-ink-3)';
          return `
            <div class="history-item" style="cursor:default;">
              <div class="history-item-top">
                <span class="history-item-time scanner-mono">${dev.ip}</span>
                <span style="display:inline-flex; align-items:center; gap:4px; font-size:11px; color:${statusColor};">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:${statusColor};"></span>${dev.status || '-'}
                </span>
              </div>
              <div class="history-item-meta">${dev.hostname || dev.type || '-'} · ${dev.mac ? dev.mac.toUpperCase() : 'MAC 缺失'}</div>
              ${dev.latency != null ? `<div class="history-item-sub">延迟 ${dev.latency}ms${dev.services && dev.services.length ? ' · 服务 ' + dev.services.map(s => typeof s === 'object' ? s.name : s).join(', ') : ''}</div>` : ''}
            </div>
          `;
        }).join('')}
      </div>
      <div style="padding:8px 14px; border-top:1px solid var(--scanner-border);">
        <button class="action-btn" id="history-back-btn" style="width:100%; justify-content:center;">
          <i data-lucide="arrow-left"></i> 返回历史列表
        </button>
      </div>
    `;
    document.getElementById('history-back-btn').addEventListener('click', showHistoryPanel);
    lucide.createIcons();
  }

  function clearHistory() {
    if (!confirm('确定清空所有扫描历史记录吗？此操作不可撤销。')) return;
    localStorage.removeItem(HISTORY_KEY);
    showToast('历史记录已清空');
    showHistoryPanel();
  }

  function bindEvents() {
    els.btnStart.addEventListener('click', startScan);
    els.btnStop.addEventListener('click', stopScan);
    els.btnExport.addEventListener('click', exportResult);

    // 点击软件名称显示关于对话框
    document.getElementById('app-about')?.addEventListener('click', () => {
      if (api && api.showAbout) {
        api.showAbout();
      }
    });

    document.querySelectorAll('.mode-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        currentMode = btn.dataset.mode;
        updateModeButtons();
      });
    });

    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        currentFilter = btn.dataset.filter;
        updateFilterButtons();
        renderDevices();
      });
    });

    // 选项卡切换
    const tabTopology = document.getElementById('tab-topology');
    const tabDeviceList = document.getElementById('tab-devicelist');
    const panelTopology = document.getElementById('panel-topology');
    const panelDeviceList = document.getElementById('panel-devicelist');
    const topoLegend = document.getElementById('topo-legend');
    const deviceFilters = document.getElementById('device-filters');
    const resultMeta = document.getElementById('result-meta');

    function switchTab(tab) {
      const isTopo = tab === 'topology';
      // 按钮样式
      if (tabTopology) {
        tabTopology.className = isTopo
          ? 'tab-btn inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 border-primary text-primary transition'
          : 'tab-btn inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-muted-foreground hover:text-foreground transition';
      }
      if (tabDeviceList) {
        tabDeviceList.className = isTopo
          ? 'tab-btn inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-muted-foreground hover:text-foreground transition'
          : 'tab-btn inline-flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 border-primary text-primary transition';
      }
      // 面板显隐
      if (panelTopology) panelTopology.style.display = isTopo ? 'block' : 'none';
      if (panelDeviceList) panelDeviceList.style.display = isTopo ? 'none' : 'block';
      // 右侧控件
      if (topoLegend) topoLegend.style.display = isTopo ? '' : 'none';
      if (deviceFilters) deviceFilters.style.display = isTopo ? 'none' : 'inline-flex';
      if (resultMeta) resultMeta.style.display = isTopo ? 'none' : '';
      // 切换到拓扑图时重新渲染（确保尺寸正确）并创建图标
      if (isTopo) {
        setTimeout(() => {
          renderTopology();
          lucide.createIcons();
        }, 50);
      }
    }

    if (tabTopology) tabTopology.addEventListener('click', () => switchTab('topology'));
    if (tabDeviceList) tabDeviceList.addEventListener('click', () => switchTab('devicelist'));

    els.searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.trim();
      // 同步到移动端搜索框
      const mobileInput = document.getElementById('search-input-mobile');
      if (mobileInput && mobileInput.value !== searchQuery) mobileInput.value = searchQuery;
      renderDevices();
    });

    // 移动端搜索框
    const mobileSearchInput = document.getElementById('search-input-mobile');
    const mobileSearchSection = document.getElementById('mobile-search-section');
    const mobileSearchBtn = document.getElementById('btn-search-mobile');

    if (mobileSearchInput) {
      mobileSearchInput.addEventListener('input', (e) => {
        searchQuery = e.target.value.trim();
        // 同步到桌面端搜索框
        if (els.searchInput && els.searchInput.value !== searchQuery) els.searchInput.value = searchQuery;
        renderDevices();
      });
    }

    if (mobileSearchBtn && mobileSearchSection) {
      mobileSearchBtn.addEventListener('click', () => {
        const isShown = mobileSearchSection.style.display !== 'none';
        mobileSearchSection.style.display = isShown ? 'none' : 'block';
        if (!isShown) {
          setTimeout(() => mobileSearchInput && mobileSearchInput.focus(), 50);
        }
      });
    }

    api.onScanProgress((data) => {
      setText(els.scanElapsed, (data.elapsed / 1000).toFixed(1));
      const pct = data.total ? Math.round((data.scanned / data.total) * 100) : 0;
      els.scanProgress.style.width = `${pct}%`;

      // 更新扫描动画
      const scanLoadingPct = document.getElementById('scan-loading-pct');
      const scanLoadingDetail = document.getElementById('scan-loading-detail');
      if (scanLoadingPct) scanLoadingPct.textContent = `${pct}%`;
      if (scanLoadingDetail) {
        if (data.phase === 'started') {
          scanLoadingDetail.textContent = '正在初始化...';
        } else if (data.phase === 'portscanning') {
          scanLoadingDetail.textContent = `正在扫描开放端口... · 发现 ${data.found} 台在线`;
        } else if (data.phase === 'completed') {
          scanLoadingDetail.textContent = '扫描完成';
        } else {
          scanLoadingDetail.textContent = `已扫描 ${data.scanned}/${data.total} 台 · 发现 ${data.found} 台在线`;
        }
      }
    });

    // 设备行点击 -> 显示详情
    els.deviceTableBody.addEventListener('click', (e) => {
      const row = e.target.closest('tr[data-ip]');
      if (!row) return;
      const ip = row.dataset.ip;
      const device = devices.find(d => d.ip === ip);
      if (device) showDeviceDetail(device);
    });

    // 设备行右键 -> 上下文菜单
    els.deviceTableBody.addEventListener('contextmenu', (e) => {
      const row = e.target.closest('tr[data-ip]');
      if (!row) return;
      e.preventDefault();
      const ip = row.dataset.ip;
      const device = devices.find(d => d.ip === ip);
      if (device) showContextMenu(device, e.clientX, e.clientY);
    });

    // 拓扑图节点点击 -> 显示详情
    document.getElementById('topology-nodes').addEventListener('click', (e) => {
      const card = e.target.closest('.topo-node-card');
      if (!card) return;
      const ip = card.dataset.topoIp;
      const device = devices.find(d => d.ip === ip);
      if (device) showDeviceDetail(device);
    });

    // 拓扑图节点右键 -> 上下文菜单
    document.getElementById('topology-nodes').addEventListener('contextmenu', (e) => {
      const card = e.target.closest('.topo-node-card');
      if (!card) return;
      e.preventDefault();
      const ip = card.dataset.topoIp;
      const device = devices.find(d => d.ip === ip);
      if (device) showContextMenu(device, e.clientX, e.clientY);
    });

    // 全局点击关闭右键菜单
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.ctx-menu')) hideContextMenu();
    });
    document.addEventListener('contextmenu', (e) => {
      if (!e.target.closest('tr[data-ip]') && !e.target.closest('.topo-node-card')) {
        hideContextMenu();
      }
    });

    // 操作面板折叠
    document.querySelectorAll('.action-panel-header').forEach(header => {
      header.addEventListener('click', () => {
        const panel = header.closest('.action-panel');
        if (panel) panel.classList.toggle('collapsed');
      });
    });

    // Ping 测试按钮
    document.getElementById('ping-run-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runPingTest(currentDetailDevice);
    });
    document.getElementById('ping-clear-btn')?.addEventListener('click', () => {
      resetActionPanels();
    });

    // 端口扫描按钮
    document.getElementById('portscan-run-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runPortScan(currentDetailDevice, 'common');
    });
    document.getElementById('portscan-full-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runPortScan(currentDetailDevice, 'full');
    });

    // 历史记录按钮
    document.getElementById('btn-history')?.addEventListener('click', () => {
      const panel = document.getElementById('history-panel');
      if (panel.style.display === 'flex') {
        panel.style.display = 'none';
      } else {
        showHistoryPanel();
      }
    });
    document.getElementById('history-close-btn')?.addEventListener('click', () => {
      document.getElementById('history-panel').style.display = 'none';
    });
    document.getElementById('history-clear-btn')?.addEventListener('click', clearHistory);

    // 告警按钮
    document.getElementById('btn-alerts')?.addEventListener('click', () => {
      const panel = document.getElementById('history-panel');
      if (panel.style.display === 'flex' && panel.querySelector('.history-panel-header h3').textContent.includes('告警')) {
        panel.style.display = 'none';
      } else {
        showAlertsPanel();
      }
    });

    // 连续监控停止按钮
    document.getElementById('monitor-stop-btn')?.addEventListener('click', stopMonitor);

    // 缩放控件
    document.getElementById('topo-zoom-in')?.addEventListener('click', () => applyTopoScale(topoScale + 0.15));
    document.getElementById('topo-zoom-out')?.addEventListener('click', () => applyTopoScale(topoScale - 0.15));
    document.getElementById('topo-zoom-fit')?.addEventListener('click', () => {
      topoPan.x = 0;
      topoPan.y = 0;
      applyTopoScale(1);
    });

    // 窗口大小变化时重新渲染拓扑图
    let topoResizeTimer = null;
    window.addEventListener('resize', () => {
      if (topoResizeTimer) clearTimeout(topoResizeTimer);
      topoResizeTimer = setTimeout(() => renderTopology(), 200);
    });

    // 关闭弹窗
    document.getElementById('detail-close').addEventListener('click', hideDeviceDetail);
    document.getElementById('device-detail-overlay').addEventListener('click', (e) => {
      if (e.target.id === 'device-detail-overlay') hideDeviceDetail();
    });

    // ESC 关闭抽屉/历史面板
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        hideContextMenu();
        document.getElementById('history-panel').style.display = 'none';
      }
    });
  }

  async function init() {
    try {
      localInfo = await api.getLocalInfo();
      selectedAdapter = localInfo.activeAdapter || localInfo.adapters[0] || null;
      renderLocalInfo();
      updateScanTarget();
      updateModeButtons();
      updateFilterButtons();
      renderDevices();
    } catch (err) {
      console.error('Init error:', err);
      setText(els.localIp, '初始化失败');
    } finally {
      bindEvents();
    }
  }

  init();
})();
