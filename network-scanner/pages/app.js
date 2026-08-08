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
  let scanAborted = false;

  // 新增状态
  let currentDetailDevice = null;
  let monitorTimer = null;
  let monitorStats = { success: 0, total: 0, latencies: [], history: [] };
  let activeAlerts = [];

  // 设备元数据缓存（备注 / 标签 / 收藏 / 分组）
  let deviceMeta = { devices: {}, groups: [] };

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
    scanPctText: document.getElementById('scan-pct-text'),
    btnStart: document.getElementById('btn-start'),
    btnStop: document.getElementById('btn-stop'),
    btnExport: document.getElementById('btn-export'),
    statDevices: document.getElementById('stat-devices'),
    statOnline: document.getElementById('stat-online'),
    statCoveragePct: document.getElementById('stat-coverage-pct'),
    statCoverageBar: document.getElementById('stat-coverage-bar'),
    statLatency: document.getElementById('stat-latency'),
    statLatencyMin: document.getElementById('stat-latency-min'),
    statLatencyMax: document.getElementById('stat-latency-max'),
    statLatencyLevel: document.getElementById('stat-latency-level'),
    statTime: document.getElementById('stat-time'),
    statFingerprints: document.getElementById('stat-fingerprints'),
    statServicesTotal: document.getElementById('stat-services-total'),
    statEvidence: document.getElementById('stat-evidence'),
    statEvidenceBadge: document.getElementById('stat-evidence-badge'),
    deviceCount: document.getElementById('device-count'),
    deviceCidr: document.getElementById('device-cidr'),
    deviceTableBody: document.getElementById('device-table-body'),
    emptyState: document.getElementById('empty-state'),
    searchInput: document.getElementById('search-input'),
    sideStatHistory: document.getElementById('side-stat-history'),
    sideStatDevicesEver: document.getElementById('side-stat-devices-ever'),
    sideStatAvgRate: document.getElementById('side-stat-avg-rate')
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
      const iconStyle = device.type === '本机'
        ? 'background: linear-gradient(135deg, var(--scanner-primary-100), var(--scanner-primary-50)); color: var(--scanner-primary);'
        : 'background: linear-gradient(135deg, var(--scanner-state-info-100), var(--scanner-muted)); color: var(--scanner-state-info);';

      const badges = getDeviceTypeBadges(device);
      const badgeHtml = badges.map(b => `<span class="inline-flex items-center text-[11px] font-bold px-2.5 py-1 rounded-lg ${b.cls}">${b.text}</span>`).join(' ');

      // 状态徽章：按状态值上色 + 更大尺寸
      let statusBg, statusColor;
      if (device.status === '在线') { statusBg = 'var(--scanner-state-success-100)'; statusColor = 'var(--scanner-state-success)'; }
      else if (device.status === '离线') { statusBg = 'var(--scanner-muted)'; statusColor = 'var(--scanner-ink-3)'; }
      else { statusBg = 'var(--scanner-state-warning-100)'; statusColor = 'var(--scanner-state-warning)'; }
      const statusHtml = `
        <span class="inline-flex items-center gap-1.5 text-[11.5px] font-bold px-3 py-1.5 rounded-full shadow-1" style="background:${statusBg}; color:${statusColor};">
          <span class="w-2 h-2 rounded-full bg-current animate-pulse"></span>${device.status}
        </span>`;

      const hostLine = device.hostname || (device.type === '本机' ? localInfo?.hostname : device.type || '-');
      const macLine = device.mac ? device.mac.toUpperCase() : '—';

      // 延迟：按数值上色 + 胶囊
      let latHtml;
      if (device.latency != null) {
        const lat = device.latency;
        let lbg, lcol;
        if (lat < 50)      { lbg = 'var(--scanner-state-success-100)'; lcol = 'var(--scanner-state-success)'; }
        else if (lat < 150){ lbg = 'var(--scanner-state-info-100)';    lcol = 'var(--scanner-state-info)'; }
        else if (lat < 300){ lbg = 'var(--scanner-state-warning-100)'; lcol = 'var(--scanner-state-warning)'; }
        else               { lbg = 'var(--scanner-state-error-100)';   lcol = 'var(--scanner-state-error)'; }
        latHtml = `<span class="inline-flex items-center px-3 py-1.5 rounded-lg text-[12px] font-black scanner-mono shadow-1" style="background:${lbg}; color:${lcol};">${lat.toFixed(0)} <span class="text-[9.5px] ml-0.5 font-semibold opacity-80">ms</span></span>`;
      } else latHtml = '<span class="text-muted-foreground text-[12px] font-semibold">—</span>';

      // 服务：数量胶囊 + 端口预览
      let svcHtml;
      if (device.services && device.services.length) {
        const total = device.services.length;
        const topPorts = device.services
          .slice(0, 2)
          .map(s => typeof s === 'object' ? s.port : String(s).match(/(\d+)\s*\/?([A-Za-z]*)/)?.[1] || s)
          .join(', ');
        const more = total > 2 ? `+${total - 2}` : '';
        svcHtml = `
          <div class="flex flex-col gap-1">
            <span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-black text-[12px] shadow-1" style="background:var(--scanner-state-success-100); color:var(--scanner-state-success);">
              <i data-lucide="layers" class="w-3 h-3"></i>
              ${total} 个
            </span>
            ${topPorts ? `<span class="text-[10.5px] font-semibold scanner-mono text-muted-foreground leading-none">${topPorts}${more ? ` ${more}` : ''}</span>` : ''}
          </div>`;
      } else svcHtml = '<span class="text-muted-foreground text-[12px] font-semibold">—</span>';

      return `
        <tr class="border-b border-border hover:bg-muted/50 transition device-row-enter" data-ip="${device.ip}" style="cursor:pointer;">
          <td class="px-5 py-4 align-middle">
            <div class="flex items-center gap-2.5">
              <div class="w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${iconColor}" style="${iconStyle}">
                <i data-lucide="${icon}" class="w-4.5 h-4.5"></i>
              </div>
              <div class="min-w-0">
                <span class="block text-[13px] font-bold scanner-mono text-foreground leading-none">${device.ip}</span>
                ${device.manufacturer ? `<span class="block text-[10.5px] text-muted-foreground mt-1 leading-none truncate" style="max-width:160px;">${device.manufacturer}</span>` : ''}
              </div>
            </div>
          </td>
          <td class="px-5 py-4 align-middle">${badgeHtml || '<span class="text-[11px] text-muted-foreground font-semibold">未知</span>'}</td>
          <td class="px-5 py-4 align-middle">${statusHtml}</td>
          <td class="px-5 py-4 align-middle">
            <div class="min-w-0">
              <div class="text-[13px] font-bold text-foreground truncate leading-tight" style="max-width:220px;">${hostLine}</div>
              <div class="text-[10.5px] scanner-mono text-muted-foreground mt-1 leading-tight">${macLine}</div>
            </div>
          </td>
          <td class="px-5 py-4 align-middle">${svcHtml}</td>
          <td class="px-5 py-4 align-middle">${latHtml}</td>
        </tr>
      `;
    }).join('');
    lucide.createIcons();
    renderTopology();

    // 同步侧栏「扫描概览」三小卡数据
    refreshSidebarOverviewStats();
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

    // 渲染卡片（放大尺寸，保证 IP/类型/图标/主机名/厂商/MAC/状态 全部完整显示）
    const nodeWidth = 220;       // 原 180 → 220，避免横向被挤压后文字缩太小
    const nodeHeight = 120;      // 原 90 → 120，至少容纳：图标行 + badges + MAC行 + 状态行
    const layerGap = 70;         // 原 60 → 70，卡片变大后层级间距略增防重叠
    const nodeGap = 22;          // 原 20 → 22，相邻卡片间距更安全
    const padding = 48;

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

    // 让容器、节点层、SVG层都使用明确的实际像素尺寸，
    // 保证父 div 被内容完全撑大，不会因 % 高度 + overflow 而裁剪
    nodesEl.style.width = canvasWidth + 'px';
    nodesEl.style.height = canvasHeight + 'px';
    edgesEl.setAttribute('width', canvasWidth);
    edgesEl.setAttribute('height', canvasHeight);
    edgesEl.style.width = canvasWidth + 'px';
    edgesEl.style.height = canvasHeight + 'px';
    if (container) {
      container.style.minHeight = (canvasHeight + 60) + 'px';
    }

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

    // 容器已改为自适应撑大（非固定高度裁剪）：
    // 1) 仅当水平方向不够宽时才做缩小，保证不横向溢出；
    // 2) 垂直方向不再用 containerHeight 计算居中（避免容器很大时内容被推到屏幕外），
    //    保持 Y=0 让布局自然从顶部开始，用户可自然向下滚动查看全部节点。
    topoScale = 1;
    const freshContainer = document.getElementById('topology-container');
    if (freshContainer) {
      const containerWidth = freshContainer.clientWidth;
      // 仅基于宽度计算缩放；最小 0.75 保证 220×120 卡片缩完后仍约 165×90，
      // 文字 12px → 9px，IP/主机名/MAC/状态均能完整识别不糊
      const hScale = (containerWidth - 40) / canvasWidth;
      topoScale = Math.max(0.75, Math.min(1, hScale));
      topoPan.x = Math.max(0, (containerWidth - canvasWidth * topoScale) / 2);
      topoPan.y = 20; // 仅保留 20px 顶部边距，避免推到太下
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

    // 鼠标滚轮缩放（下限 0.75，保证卡片内容始终可读）
    curContainer.addEventListener('wheel', (e) => {
      if (e.target.closest('.topo-node-card')) return;
      e.preventDefault();
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      applyTopoScale(Math.max(0.75, Math.min(2, topoScale + delta)));
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

    // 属性徽章（最多只显示 1 个，避免 3 个 badge 折行导致高度不够）
    const badges = [];
    if (isGateway) badges.push('路由器');
    if (device.isPrivate) badges.push('私有');
    if (device.manufacturer) {
      // 厂商标过长时截断，避免横向溢出导致换行
      const short = device.manufacturer.length > 8
        ? device.manufacturer.slice(0, 7) + '…'
        : device.manufacturer;
      badges.push(short);
    }
    const displayBadges = badges.slice(0, 1);

    // 状态行
    const statusDotColor = isOnline ? 'var(--scanner-state-success)' : 'var(--scanner-state-warning)';
    const statusText = isOnline ? '在线' : (device.status || '未知');
    const latencyText = device.latency != null && device.latency >= 0 ? `${device.latency.toFixed(0)}ms` : '';

    const badgesHtml = displayBadges.length > 0
      ? displayBadges.map(b => `<span style="font-size:9px; padding:1px 5px; border-radius:3px; background:var(--scanner-muted); color:var(--scanner-ink-2); white-space:nowrap;">${b}</span>`).join(' ')
      : '';

    const macHtml = device.mac
      ? `<span style="font-size:9.5px; line-height:1.3; color:var(--scanner-ink-3); font-family:var(--scanner-font-mono); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">MAC ${device.mac}</span>`
      : '';

    const statusHtml = isInternet ? '' : `
      <div style="display:flex; align-items:center; gap:5px; font-size:9.5px; line-height:1.3;">
        <span style="display:inline-flex; align-items:center; gap:3px;">
          <span style="width:5px; height:5px; border-radius:50%; background:${statusDotColor}; display:inline-block; flex-shrink:0;"></span>
          <span style="color:${statusDotColor};">${statusText}</span>
        </span>
        ${latencyText ? `<span style="color:var(--scanner-ink-3);">· ${latencyText}</span>` : ''}
      </div>
    `;

    // 关键修复：
    // 1) 去掉 overflow:hidden —— 不再裁剪内部内容
    // 2) 固定 height:${h}px 仍保留（布局计算依赖），但改为 min-height 并允许内容超一点时自然超出
    // 3) 内边距略收紧，避免浪费空间
    return `
      <div class="topo-node-card" data-topo-ip="${device.ip || ''}" style="position:absolute; left:${x}px; top:${y}px; width:${w}px; min-height:${h}px; background:${bgColor}; border:1px solid ${borderColor}; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.08); overflow:visible; cursor:pointer; transition: box-shadow 0.2s; user-select:none; box-sizing:border-box;" onmouseover="this.style.boxShadow='0 4px 16px rgba(0,0,0,0.12)'" onmouseout="this.style.boxShadow='0 2px 8px rgba(0,0,0,0.08)'">
        <div style="padding:8px 10px; box-sizing:border-box;">
          <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:5px; gap:6px;">
            <span style="font-size:12px; font-weight:600; font-family:var(--scanner-font-mono); color:${textColor}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; min-width:0; flex:1;">${device.ip || '?'}</span>
            <span style="font-size:9px; padding:2px 6px; border-radius:4px; background:${badgeColor}; color:${badgeTextColor}; font-weight:500; white-space:nowrap; flex-shrink:0;">${typeLabel}</span>
          </div>
          <div style="display:flex; align-items:flex-start; gap:7px; margin-bottom:${isInternet ? '0' : '4px'};">
            <div style="width:24px; height:24px; border-radius:5px; background:${iconBg}; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
              <i data-lucide="${iconName}" style="width:13px; height:13px; color:${iconColor};"></i>
            </div>
            <div style="flex:1; min-width:0;">
              <div style="font-size:11.5px; color:${textColor}; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; line-height:1.3;">${device.hostname || device.type || '未知设备'}</div>
              ${badgesHtml ? `<div style="display:flex; gap:3px; margin-top:3px; overflow:hidden;">${badgesHtml}</div>` : ''}
            </div>
          </div>
          ${isInternet ? '' : `
            <div style="display:flex; flex-direction:column; gap:3px; margin-top:5px; padding-top:5px; border-top:1px solid ${borderColor};">
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
    const nodeHeight = 120; // 与 renderTopology 节点卡片实际高度保持一致

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

  // 缩放（下限 0.75，保证节点卡片 IP/主机名/MAC/状态等文字能完整识别）
  function applyTopoScale(scale) {
    topoScale = Math.max(0.75, Math.min(2, scale));
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
    const servicesTotal = devices.reduce((n, d) => n + (d.services ? d.services.length : 0), 0);

    // 证据缺失的细分（MAC/厂商/主机名/端口）
    const missingMac = devices.filter(d => !d.mac).length;
    const missingVendor = devices.filter(d => !d.manufacturer).length;
    const missingHostname = devices.filter(d => !d.hostname).length;
    const missingPorts = devices.filter(d => !d.services || d.services.length === 0).length;
    const pending = devices.length === 0 ? 0 : Math.max(missingMac, missingVendor, missingHostname, missingPorts);

    setText(els.statDevices, devices.length.toString());
    setText(els.statOnline, online.toString());
    setText(els.statLatency, avg);
    setText(els.statFingerprints, withServices.toString());
    setText(els.statEvidence, pending.toString());

    // ── 汇总卡新增字段 ──────────────────────────────────────
    // Card1: 扫描完成度
    const totalHostsN = parseInt(els.scanHosts ? (els.scanHosts.textContent || '0') : '0', 10) || 0;
    const coveragePct = totalHostsN > 0
      ? Math.min(100, Math.round((devices.length / totalHostsN) * 100))
      : (devices.length > 0 ? 100 : 0);
    setText(els.statCoveragePct, coveragePct + '%');
    if (els.statCoverageBar) els.statCoverageBar.style.width = coveragePct + '%';

    // Card2: 最快/最慢延迟 + 等级徽章
    if (latencies.length > 0) {
      const mn = Math.min(...latencies);
      const mx = Math.max(...latencies);
      setText(els.statLatencyMin, mn.toFixed(0));
      setText(els.statLatencyMax, mx.toFixed(0));
      if (els.statLatencyLevel) {
        const avgNum = parseFloat(avg) || 0;
        let label, colorBg, colorFg;
        if (avgNum < 50)       { label = '极速'; colorBg = 'var(--scanner-state-success-100)'; colorFg = 'var(--scanner-state-success)'; }
        else if (avgNum < 150) { label = '良好'; colorBg = 'var(--scanner-state-info-100)';    colorFg = 'var(--scanner-state-info)'; }
        else if (avgNum < 300) { label = '一般'; colorBg = 'var(--scanner-state-warning-100)'; colorFg = 'var(--scanner-state-warning)'; }
        else                   { label = '较差'; colorBg = 'var(--scanner-state-error-100)';   colorFg = 'var(--scanner-state-error)'; }
        els.statLatencyLevel.textContent = label;
        els.statLatencyLevel.style.background = colorBg;
        els.statLatencyLevel.style.color = colorFg;
      }
    } else {
      setText(els.statLatencyMin, '-');
      setText(els.statLatencyMax, '-');
      if (els.statLatencyLevel) { els.statLatencyLevel.textContent = '-'; els.statLatencyLevel.style.background = 'var(--scanner-muted)'; els.statLatencyLevel.style.color = 'var(--scanner-ink-2)'; }
    }

    // Card3: 服务端口总数
    setText(els.statServicesTotal, servicesTotal.toString());

    // Card4: 待补证据等级徽章 + 各缺失类型高亮
    if (devices.length === 0) {
      if (els.statEvidenceBadge) { els.statEvidenceBadge.textContent = '无数据'; els.statEvidenceBadge.style.background = 'var(--scanner-muted)'; els.statEvidenceBadge.style.color = 'var(--scanner-ink-2)'; }
    } else {
      const ratio = pending / devices.length;
      let label, colorBg, colorFg;
      if (ratio <= 0.1)      { label = '非常完整'; colorBg = 'var(--scanner-state-success-100)'; colorFg = 'var(--scanner-state-success)'; }
      else if (ratio <= 0.4) { label = '基本完整'; colorBg = 'var(--scanner-state-info-100)';    colorFg = 'var(--scanner-state-info)'; }
      else if (ratio <= 0.7) { label = '缺较多';   colorBg = 'var(--scanner-state-warning-100)'; colorFg = 'var(--scanner-state-warning)'; }
      else                   { label = '严重缺失'; colorBg = 'var(--scanner-state-error-100)';   colorFg = 'var(--scanner-state-error)'; }
      if (els.statEvidenceBadge) { els.statEvidenceBadge.textContent = label; els.statEvidenceBadge.style.background = colorBg; els.statEvidenceBadge.style.color = colorFg; }
    }
    // 4类缺失：有缺失的高亮（不透明），否则淡出（opacity 0.3）
    function setChipActive(id, active) {
      const el = document.getElementById(id);
      if (!el) return;
      el.style.opacity = active ? '1' : '0.3';
      el.style.outline = active ? '1px solid currentColor' : 'none';
    }
    setChipActive('stat-chip-mac',      missingMac > 0);
    setChipActive('stat-chip-vendor',   missingVendor > 0);
    setChipActive('stat-chip-hostname', missingHostname > 0);
    setChipActive('stat-chip-ports',    missingPorts > 0);

    // 同步侧栏「扫描概览」
    refreshSidebarOverviewStats();
  }

  /**
   * 刷新侧边栏底部「扫描概览」三小卡：累计扫描 / 累计发现 / 在线率
   * 数据来源：localStorage 历史记录 + 当前内存中的 devices
   */
  function refreshSidebarOverviewStats() {
    const history = (typeof loadHistory === 'function') ? (loadHistory() || []) : [];

    // 累计扫描次数（含本次如果已经开始跑且有设备）
    const historyCount = history.length;
    const pendingRun = !historyCount || devices.length > 0 ? 1 : 0;
    const totalRuns = historyCount + (history.length === 0 && devices.length === 0 ? 0 : pendingRun);
    setText(els.sideStatHistory, totalRuns.toString());

    // 累计发现设备（历史 totalCount + 当前 devices.length，避免重复）
    const historyDevices = history.reduce((s, h) => s + (parseInt(h.totalCount) || 0), 0);
    setText(els.sideStatDevicesEver, (historyDevices + devices.length).toString());

    // 在线率：优先用当前批次（devices）；否则用历史累计比值
    let onlineRate = null;
    if (devices.length > 0) {
      onlineRate = (devices.filter(d => d.status === '在线').length / devices.length) * 100;
    } else if (history.length > 0) {
      const tSum = history.reduce((s, h) => s + (parseInt(h.totalCount) || 0), 0);
      const oSum = history.reduce((s, h) => s + (parseInt(h.onlineCount) || 0), 0);
      if (tSum > 0) onlineRate = (oSum / tSum) * 100;
    }
    setText(els.sideStatAvgRate, onlineRate == null ? '-' : `${onlineRate.toFixed(0)}%`);
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
    scanAborted = false;

    scanTimer = setInterval(() => {
      setText(els.scanElapsed, ((Date.now() - scanStartTime) / 1000).toFixed(1));
    }, 200);

    const config = modeConfig[currentMode];
    const cidr = selectedAdapter ? selectedAdapter.cidr : els.scanTarget.value.replace(/.*?(\d+\.\d+\.\d+\.\d+\/\d+).*/, '$1');

    try {
      scanPromise = api.scanNetwork({ cidr, concurrency: config.concurrency, timeout: config.timeout });
      const result = await scanPromise;
      if (scanAborted) return; // 用户已停止扫描，忽略结果
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
    scanAborted = true;
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

    // 渲染设备元数据（收藏 / 标签 / 分组 / 备注）
    renderDeviceMeta(device);

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
    const aiResult = document.getElementById('ai-result');
    const diagResult = document.getElementById('diag-result');
    const customRow = document.getElementById('portscan-custom-row');
    const dnsRow = document.getElementById('diag-dns-row');
    if (pingResult) pingResult.innerHTML = '<div class="port-empty">点击"开始 Ping"进行连通性测试</div>';
    if (portscanResult) portscanResult.innerHTML = '<div class="port-empty">点击"常用端口"开始检测</div>';
    if (aiResult) aiResult.innerHTML = '<div class="port-empty">点击"分析"按钮，AI 将生成该设备的安全分析报告</div>';
    if (diagResult) diagResult.innerHTML = '<div class="port-empty">选择上方工具进行网络诊断</div>';
    if (customRow) customRow.style.display = 'none';
    if (dnsRow) dnsRow.style.display = 'none';
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
      { icon: 'sparkles', label: 'AI 智能分析', action: () => { showDeviceDetail(device); setTimeout(() => openAiAnalysis('full'), 300); } },
      { divider: true },
      { icon: 'route', label: '路由追踪', action: () => { showDeviceDetail(device); runTraceroute(device); } },
      { icon: 'gauge', label: '网速测试', action: () => { showDeviceDetail(device); runSpeedTest(device); } },
      { icon: 'power', label: 'Wake-on-LAN', action: () => { showDeviceDetail(device); runWakeOnLan(device); } },
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
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
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
  // 解析自定义端口范围字符串，如 "80,443,8080" 或 "1-1000" 或 "80,443,1000-2000"
  function parsePortRange(str) {
    const ports = [];
    const parts = str.split(',').map(s => s.trim()).filter(Boolean);
    for (const part of parts) {
      const rangeMatch = part.match(/^(\d+)-(\d+)$/);
      if (rangeMatch) {
        const start = parseInt(rangeMatch[1], 10);
        const end = parseInt(rangeMatch[2], 10);
        if (start >= 1 && end <= 65535 && start <= end) {
          for (let p = start; p <= end; p++) ports.push(p);
        }
      } else if (/^\d+$/.test(part)) {
        const p = parseInt(part, 10);
        if (p >= 1 && p <= 65535) ports.push(p);
      }
    }
    return [...new Set(ports)].sort((a, b) => a - b);
  }

  async function runPortScan(device, mode) {
    const resultEl = document.getElementById('portscan-result');
    const runBtn = document.getElementById('portscan-run-btn');
    const fullBtn = document.getElementById('portscan-full-btn');
    const customBtn = document.getElementById('portscan-custom-btn');
    if (!resultEl || !device) return;

    let ports;
    let useUdp = false;
    let useBanner = false;

    if (mode === 'custom') {
      const rangeStr = document.getElementById('portscan-custom-range')?.value || '';
      useUdp = document.getElementById('portscan-udp-check')?.checked || false;
      useBanner = document.getElementById('portscan-banner-check')?.checked || false;
      ports = parsePortRange(rangeStr);
      if (!ports.length) {
        resultEl.innerHTML = '<div class="port-empty" style="color:var(--scanner-state-warning);">请输入有效的端口范围，如 80,443 或 1-1000</div>';
        return;
      }
      if (ports.length > 2048) {
        resultEl.innerHTML = '<div class="port-empty" style="color:var(--scanner-state-warning);">端口数量过多（>2048），请缩小范围</div>';
        return;
      }
    } else if (mode === 'full') {
      ports = [];
      for (let p = 1; p <= 1024; p++) ports.push(p);
    } else {
      ports = Object.keys(PORT_SERVICES).map(Number);
    }

    runBtn.disabled = true;
    fullBtn.disabled = true;
    if (customBtn) customBtn.disabled = true;
    const modeLabel = useUdp ? 'UDP' : 'TCP';
    resultEl.innerHTML = `<div class="port-empty"><div class="action-panel-hint" style="margin-bottom:6px;">正在${modeLabel}扫描 ${ports.length} 个端口${useBanner ? '（含 Banner Grabbing）' : ''}，请稍候...</div></div>`;

    try {
      let r;
      if (useUdp) {
        r = await api.scanUdpPorts(device.ip, ports, 1500);
      } else if (useBanner || mode === 'custom') {
        r = await api.scanPortsAdvanced(device.ip, ports, { banner: useBanner, timeout: 1500 });
      } else {
        r = await api.scanPorts(device.ip, ports);
      }
      if (r.success) {
        renderPortScanResult(resultEl, r.openPorts || [], useUdp);
      } else {
        resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-error);">扫描失败: ${r.error || '未知错误'}</div>`;
      }
    } catch (err) {
      resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-error);">扫描异常: ${err.message}</div>`;
    } finally {
      runBtn.disabled = false;
      fullBtn.disabled = false;
      if (customBtn) customBtn.disabled = false;
    }
  }

  function renderPortScanResult(el, openPorts, isUdp) {
    if (!openPorts.length) {
      el.innerHTML = '<div class="port-empty">未发现开放端口</div>';
      return;
    }
    const items = openPorts.map(item => {
      const port = typeof item === 'object' ? item.port : item;
      const svcName = typeof item === 'object' ? (item.name || PORT_SERVICES[port] || '未知') : (PORT_SERVICES[port] || '未知');
      const svcDesc = typeof item === 'object' ? (item.desc || '') : (PORT_DESCRIPTIONS[port] || '');
      const banner = typeof item === 'object' ? (item.banner || '') : '';
      const riskLevel = typeof item === 'object' ? item.risk : (HIGH_RISK_PORTS.includes(port) ? 'high' : MED_RISK_PORTS.includes(port) ? 'medium' : '');
      const riskLabel = riskLevel === 'high' ? '高危' : riskLevel === 'medium' ? '中危' : '低危';
      const riskCls = riskLevel === 'high' ? 'high' : riskLevel === 'medium' ? 'med' : '';
      let risk = riskCls ? `<span class="port-risk ${riskCls}">${riskLabel}</span>` : '';
      const protoTag = isUdp ? '<span style="font-size:9px; padding:1px 4px; border-radius:3px; background:var(--scanner-state-info-bg); color:var(--scanner-state-info); font-weight:600;">UDP</span>' : '';
      return `
        <div class="port-item" style="flex-direction:column; align-items:flex-start; gap:4px; padding:10px 8px;">
          <div style="display:flex; align-items:center; gap:8px; width:100%;">
            <span class="port-num">${port}</span>
            ${protoTag}
            <span class="port-svc">${svcName}</span>
            ${risk}
          </div>
          ${svcDesc ? `<div style="font-size:11px; color:var(--scanner-ink-3); padding-left:2px;">${svcDesc}</div>` : ''}
          ${banner ? `<div style="font-size:10px; color:var(--scanner-ink-3); padding:2px 6px; border-radius:4px; background:var(--scanner-muted); font-family:monospace; word-break:break-all; width:100%;">${banner}</div>` : ''}
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
      // 同步保存到持久化数据库（JSON 文件）
      saveHistoryToDb({
        id: history[0].id,
        timestamp: history[0].time,
        cidr: cidr || '',
        elapsed: elapsed || 0,
        deviceCount: devs.length,
        onlineCount: devs.filter(d => d.status === '在线').length,
        devices: deviceSummary
      });
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
    const panel = document.getElementById('history-panel');
    const header = panel.querySelector('.history-panel-header h3');
    const isAlertPanel = header.textContent.includes('告警');

    if (isAlertPanel) {
      // 清除当前告警
      if (!confirm(`确定清除所有安全告警吗？(${activeAlerts.length} 条)`)) return;
      activeAlerts = [];
      updateAlertBadge();
      panel.style.display = 'none';
      showToast('告警已清除');
    } else {
      // 清除历史记录
      if (!confirm('确定清空所有扫描历史记录吗？此操作不可撤销。')) return;
      localStorage.removeItem(HISTORY_KEY);
      // 同步清除持久化数据库
      api.historyDbClear().catch(() => {});
      showToast('历史记录已清空');
      showHistoryPanel();
    }
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
      setText(els.scanPctText, `${pct}%`);

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
    document.getElementById('portscan-custom-btn')?.addEventListener('click', () => {
      const row = document.getElementById('portscan-custom-row');
      if (row) row.style.display = row.style.display === 'none' ? 'block' : 'none';
    });
    document.getElementById('portscan-os-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runOsDetect(currentDetailDevice);
    });

    // 网络诊断工具按钮
    document.getElementById('diag-trace-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runTraceroute(currentDetailDevice);
    });
    document.getElementById('diag-dns-btn')?.addEventListener('click', () => {
      const row = document.getElementById('diag-dns-row');
      if (row) row.style.display = row.style.display === 'none' ? 'block' : 'none';
    });
    document.getElementById('diag-dns-run-btn')?.addEventListener('click', runDnsQuery);
    document.getElementById('diag-speed-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runSpeedTest(currentDetailDevice);
    });
    document.getElementById('diag-wol-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runWakeOnLan(currentDetailDevice);
    });
    document.getElementById('diag-shutdown-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) runRemoteShutdown(currentDetailDevice);
    });

    // 设备元数据按钮（收藏 + 编辑）
    document.getElementById('detail-fav-btn')?.addEventListener('click', () => {
      if (currentDetailDevice) toggleFavorite(currentDetailDevice);
    });
    document.getElementById('detail-meta-btn')?.addEventListener('click', openMetaEditor);
    document.getElementById('meta-close')?.addEventListener('click', closeMetaEditor);
    document.getElementById('meta-overlay')?.addEventListener('click', (e) => {
      if (e.target.id === 'meta-overlay') closeMetaEditor();
    });
    document.getElementById('meta-save-btn')?.addEventListener('click', saveMetaFromEditor);
    document.getElementById('meta-delete-btn')?.addEventListener('click', deleteDeviceMetaFromEditor);

    // 可视化统计面板
    document.getElementById('btn-viz')?.addEventListener('click', () => {
      const panel = document.getElementById('viz-panel');
      if (panel.style.display === 'flex') {
        hideVizPanel();
      } else {
        showVizPanel();
      }
    });
    document.getElementById('viz-close-btn')?.addEventListener('click', hideVizPanel);
    document.getElementById('viz-refresh-btn')?.addEventListener('click', () => {
      renderVendorChart();
      renderPortChart();
      renderTrendChart();
      showToast('统计图表已刷新');
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

    // AI 配置弹窗
    document.getElementById('btn-ai-config')?.addEventListener('click', openAiConfig);
    document.getElementById('ai-config-close')?.addEventListener('click', closeAiConfig);
    document.getElementById('ai-config-overlay')?.addEventListener('click', (e) => {
      if (e.target.id === 'ai-config-overlay') closeAiConfig();
    });
    document.getElementById('ai-test-btn')?.addEventListener('click', testAiConnection);
    document.getElementById('ai-fetch-models-btn')?.addEventListener('click', fetchModels);
    document.getElementById('ai-provider')?.addEventListener('change', (e) => applyProviderSelection(e.target.value));
    document.getElementById('ai-save-btn')?.addEventListener('click', saveAiConfig);

    // AI 分析按钮（三种分析类型）—— 命中缓存直接显示，否则发起分析
    document.querySelectorAll('.ai-type-btn').forEach(btn => {
      btn.addEventListener('click', () => openAiAnalysis(btn.dataset.type));
    });
    document.getElementById('ai-config-link')?.addEventListener('click', openAiConfig);

    // ESC 关闭抽屉/历史面板 / 退出全屏 AI 页
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        hideContextMenu();
        document.getElementById('history-panel').style.display = 'none';
        // 退出全屏 AI 页
        const page = document.getElementById('ai-full-page');
        if (page && page.style.display !== 'none') exitFullAiPage();
      }
      // Alt+1 / Alt+2 / Alt+3 快捷键切换三种 AI 分析（命中缓存直接显示）
      if (e.altKey && (e.key === '1' || e.key === '2' || e.key === '3')) {
        e.preventDefault();
        const map = { '1': 'profile', '2': 'security', '3': 'full' };
        const type = map[e.key];
        openAiAnalysis(type);
      }
      // Alt+Enter 从侧栏 AI 结果进入全屏页
      if (e.altKey && e.key === 'Enter') {
        const el = document.getElementById('ai-analysis-result') || document.querySelector('.ai-analysis-result');
        if (el && window.__aiLastResult && window.__aiLastResult.rawText) {
          e.preventDefault();
          aiFullState.type = window.__aiLastResult.type || 'full';
          enterFullAiPage(aiFullState.type);
          renderFullAiResult(window.__aiLastResult.rawText);
        }
      }
    });

    // 全屏 AI 页：类型切换按钮（命中缓存直接显示，无缓存发起分析）
    ['profile', 'security', 'full'].forEach(type => {
      const btn = document.getElementById('ai-full-type-' + type);
      if (!btn) return;
      btn.addEventListener('click', () => openAiAnalysis(type, { target: 'full' }));
    });
  }

  // 高亮全屏页上的 AI 类型按钮
  function setFullAiTypeBtnActive(type) {
    ['profile', 'security', 'full'].forEach(t => {
      const btn = document.getElementById('ai-full-type-' + t);
      if (!btn) return;
      btn.classList.toggle('primary', t === type);
    });
  }

  // ── AI 模型配置与分析 ──────────────────────────────

  const AI_CFG_LS_KEY = 'ai-config-fallback';
  let aiConfigCache = null;
  let aiStreamCleanup = null;
  let aiAnalyzing = false;
  const isElectron = !!(api && typeof api === 'object');

  // AI 结果缓存：key = `${deviceIp}__${analysisType}`，value = { text, time, riskLevel }
  const AI_RESULT_CACHE = new Map();
  const aiCacheKey = (ip, type) => `${String(ip || '')}__${String(type || '')}`;
  // 当前选中设备下的缓存查询/写入
  function getCachedAiResult(type) {
    const key = aiCacheKey(currentDetailDevice?.ip, type);
    return AI_RESULT_CACHE.get(key) || null;
  }
  function setCachedAiResult(type, payload) {
    const key = aiCacheKey(currentDetailDevice?.ip, type);
    AI_RESULT_CACHE.set(key, payload);
  }
  function clearCachedAiResult(type) {
    const key = aiCacheKey(currentDetailDevice?.ip, type);
    AI_RESULT_CACHE.delete(key);
  }
  // 统一入口：优先显示缓存，若无则调用 runAiAnalysis；force=true 跳过缓存强制重新分析
  function openAiAnalysis(type, { force = false, target = 'auto' } = {}) {
    if (!type) type = 'full';
    const device = currentDetailDevice;
    if (!device) { showToast('请先选择一个设备'); return; }
    setActiveAiType(type);

    const fullPage = document.getElementById('ai-full-page');
    const inFullPage = target === 'full' || (target === 'auto' && !!(fullPage && fullPage.style.display !== 'none'));

    // 全屏页切换类型时，先进入对应 UI
    if (inFullPage) {
      aiFullState.type = type;
      setFullAiTypeBtnActive(type);
      enterFullAiPage(type);
    }

    // force 或无缓存 → 真正发起分析
    const cached = force ? null : getCachedAiResult(type);
    if (cached && cached.text) {
      renderAiResultFromCache(type, cached, inFullPage);
      return;
    }
    if (inFullPage) {
      setTimeout(() => runAiAnalysis(type), 50);
    } else {
      runAiAnalysis(type);
    }
  }
  // 把缓存结果渲染到侧栏 / 全屏页
  function renderAiResultFromCache(type, cached, inFullPage) {
    const finalText = cached.text;
    const typeLabels = { profile: '用户画像分析', security: '安全风险分析', full: '综合分析' };
    const typeLabel = typeLabels[type] || '综合分析';
    // 同步更新最近结果（方便其它入口引用）
    window.__aiLastResult = { type, text: finalText, time: cached.time || Date.now() };

    // 侧栏
    const resultEl = document.getElementById('ai-result');
    if (resultEl) {
      const html = renderMarkdown(finalText);
      resultEl.innerHTML =
        '<div class="ai-result-toolbar">' +
          '<span class="ai-result-label"><i data-lucide="check-circle" style="width:12px;height:12px;color:var(--scanner-state-success);"></i> ' + typeLabel + ' · 缓存</span>' +
          '<div class="ai-result-actions">' +
            '<button class="ai-result-btn" id="ai-fullscreen-btn"><i data-lucide="maximize-2" style="width:11px;height:11px;"></i> 展开查看</button>' +
            '<button class="ai-result-btn" id="ai-copy-btn"><i data-lucide="copy" style="width:11px;height:11px;"></i> 复制</button>' +
            '<button class="ai-result-btn" id="ai-retry-btn"><i data-lucide="refresh-cw" style="width:11px;height:11px;"></i> 重新分析</button>' +
          '</div>' +
        '</div>' +
        '<div class="ai-analysis-content">' + html + '</div>';
      document.getElementById('ai-copy-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(finalText).then(() => showToast('已复制到剪贴板'));
      });
      document.getElementById('ai-retry-btn')?.addEventListener('click', () => openAiAnalysis(type, { force: true }));
      document.getElementById('ai-fullscreen-btn')?.addEventListener('click', () => {
        aiFullState.type = type;
        enterFullAiPage(type);
        const riskLevel = cached.riskLevel || 'low';
        renderFullAiResult(type, finalText, riskLevel);
        const tEl = document.getElementById('ai-full-time');
        if (tEl) tEl.textContent = cached.time ? formatRelTime(cached.time) : '缓存';
        try { lucide.createIcons(); } catch (_) {}
      });
    }

    // 全屏页可见时，同步渲染
    if (inFullPage) {
      const riskLevel = cached.riskLevel || 'low';
      renderFullAiResult(type, finalText, riskLevel);
      const tEl = document.getElementById('ai-full-time');
      if (tEl) tEl.textContent = cached.time ? formatRelTime(cached.time) : '缓存';
    }
    try { lucide.createIcons(); } catch (_) {}
  }
  function formatRelTime(ts) {
    if (!ts) return '缓存';
    const diff = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (diff < 60) return diff <= 5 ? '刚刚' : diff + ' 秒前';
    if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
    if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
    return Math.floor(diff / 86400) + ' 天前';
  }

  async function loadAiConfig() {
    if (aiConfigCache) return aiConfigCache;
    if (isElectron && api.aiGetConfig) {
      try {
        aiConfigCache = await api.aiGetConfig();
      } catch (e) { /* ignore */ }
    }
    if (!aiConfigCache) {
      try {
        const raw = localStorage.getItem(AI_CFG_LS_KEY);
        if (raw) aiConfigCache = JSON.parse(raw);
      } catch (e) { /* ignore */ }
    }
    return aiConfigCache;
  }

  // ── 供应商预设数据 ──
  const AI_PROVIDERS = {
    custom:     { name: '自定义', baseUrl: '', apiFormat: 'openai-chat', models: [], keyHint: '填写对应服务商的 API Key', keyPlaceholder: 'sk-...' },
    openai:     { name: 'OpenAI', baseUrl: 'https://api.openai.com/v1', apiFormat: 'openai-chat', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'], keyHint: 'OpenAI API Key（sk- 开头）', keyPlaceholder: 'sk-...' },
    deepseek:   { name: 'DeepSeek', baseUrl: 'https://api.deepseek.com/v1', apiFormat: 'openai-chat', models: ['deepseek-chat', 'deepseek-reasoner'], keyHint: 'DeepSeek API Key', keyPlaceholder: 'sk-...' },
    zhipu:      { name: '智谱 AI', baseUrl: 'https://open.bigmodel.cn/api/paas/v4', apiFormat: 'openai-chat', models: ['glm-4-plus', 'glm-4-flash', 'glm-4-air', 'glm-4-airx', 'glm-4-long', 'glm-4v', 'glm-4v-flash'], keyHint: '智谱 API Key', keyPlaceholder: 'xxx.xxx' },
    moonshot:   { name: 'Moonshot', baseUrl: 'https://api.moonshot.cn/v1', apiFormat: 'openai-chat', models: ['moonshot-v1-8k', 'moonshot-v1-32k', 'moonshot-v1-128k'], keyHint: 'Moonshot API Key（sk- 开头）', keyPlaceholder: 'sk-...' },
    qwen:       { name: '通义千问', baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', apiFormat: 'openai-chat', models: ['qwen-plus', 'qwen-turbo', 'qwen-max', 'qwen-long'], keyHint: '阿里云 DashScope API Key', keyPlaceholder: 'sk-...' },
    baidu:      { name: '文心一言', baseUrl: 'https://qianfan.baidubce.com/v2', apiFormat: 'openai-chat', models: ['ernie-4.0-turbo-8k', 'ernie-4.0-8k-latest', 'ernie-3.5-8k', 'ernie-speed-128k'], keyHint: '百度千帆 API Key', keyPlaceholder: '...' },
    minimax:    { name: 'MiniMax', baseUrl: 'https://api.minimax.chat/v1', apiFormat: 'openai-chat', models: ['abab6.5s-chat', 'abab6.5-chat', 'abab6-chat'], keyHint: 'MiniMax API Key', keyPlaceholder: '...' },
    baichuan:   { name: '百川', baseUrl: 'https://api.baichuan-ai.com/v1', apiFormat: 'openai-chat', models: ['Baichuan4-Turbo', 'Baichuan3-Turbo', 'Baichuan2-Turbo'], keyHint: '百川 API Key', keyPlaceholder: 'sk-...' },
    yi:         { name: '零一万物', baseUrl: 'https://api.lingyiwanwu.com/v1', apiFormat: 'openai-chat', models: ['yi-large', 'yi-medium', 'yi-lightning', 'yi-vision'], keyHint: '零一万物 API Key', keyPlaceholder: '...' },
    stepfun:    { name: '阶跃星辰', baseUrl: 'https://api.stepfun.com/v1', apiFormat: 'openai-chat', models: ['step-1-8k', 'step-1-32k', 'step-1-128k', 'step-1v-8k', 'step-1v-32k'], keyHint: '阶跃星辰 API Key', keyPlaceholder: '...' },
    ollama:     { name: 'Ollama', baseUrl: 'http://localhost:11434', apiFormat: 'ollama-chat', models: ['qwen2.5:7b', 'qwen2.5:14b', 'llama3.1:8b', 'llama3.1:70b', 'deepseek-r1:7b', 'deepseek-r1:14b'], keyHint: 'Ollama 默认无需密钥，随意填写即可', keyPlaceholder: 'ollama' },
  };

  function openAiConfig() {
    const overlay = document.getElementById('ai-config-overlay');
    const statusEl = document.getElementById('ai-config-status');
    statusEl.textContent = '';
    statusEl.className = 'ai-config-status';
    overlay.style.display = 'flex';
    loadAiConfig().then(cfg => {
      if (cfg) {
        // 先填 cfg 的所有字段（即使之前保存了错误组合也先还原，再由下面反查/修正）
        document.getElementById('ai-api-format').value = cfg.apiFormat || 'openai-chat';
        document.getElementById('ai-base-url').value = cfg.baseUrl || '';
        document.getElementById('ai-api-key').value = cfg.apiKey || '';
        document.getElementById('ai-model').value = cfg.model || '';
        document.getElementById('ai-max-tokens').value = cfg.maxTokens || 2000;
        document.getElementById('ai-temperature').value = String(cfg.temperature || 0.7);

        // 先尝试 baseUrl + apiFormat 精准匹配（优先匹配精确组合）
        let providerKey = 'custom';
        for (const [k, p] of Object.entries(AI_PROVIDERS)) {
          if (p.baseUrl && cfg.baseUrl && p.baseUrl === cfg.baseUrl && p.apiFormat === (cfg.apiFormat || 'openai-chat')) {
            providerKey = k; break;
          }
        }
        // 没有精确命中的话：只要 baseUrl 命中某个服务商（说明用户选了该服务商但之前存错了 format）
        // 就自动选中该服务商，并强制修正为该服务商的正确 baseUrl + apiFormat（帮用户自动修复脏配置）
        if (providerKey === 'custom') {
          for (const [k, p] of Object.entries(AI_PROVIDERS)) {
            if (p.baseUrl && cfg.baseUrl && p.baseUrl === cfg.baseUrl) {
              providerKey = k; break;
            }
          }
        }
        document.getElementById('ai-provider').value = providerKey;
        // 最后 apply：若命中具体服务商，会强制 baseUrl / apiFormat 同步为正确的预设值并禁用编辑
        applyProviderSelection(providerKey);
      } else {
        applyProviderSelection('custom');
      }
    });
  }

  function closeAiConfig() {
    document.getElementById('ai-config-overlay').style.display = 'none';
  }

  // 供应商切换时自动填充端点、API 格式、模型列表、密钥提示
  function applyProviderSelection(providerKey) {
    const p = AI_PROVIDERS[providerKey] || AI_PROVIDERS.custom;
    const urlField = document.getElementById('ai-base-url-field');
    const urlInput = document.getElementById('ai-base-url');
    const fmtSel = document.getElementById('ai-api-format');
    const fmtHint = document.getElementById('ai-format-hint');
    const keyHint = document.getElementById('ai-api-key-hint');
    const keyInput = document.getElementById('ai-api-key');
    const modelInput = document.getElementById('ai-model');
    const datalist = document.getElementById('ai-model-list');

    if (providerKey === 'custom') {
      // 自定义模式：端点和格式都可自由编辑
      urlField.style.display = '';
      fmtSel.disabled = false;
      fmtHint.textContent = '自定义模式下请手动填写 Base URL，并选择对应服务商的 API 接口格式';
      if (!fmtSel.value) fmtSel.value = 'openai-chat';
    } else {
      // 具体服务商：端点和格式是固定匹配的，禁用格式编辑，避免用户手动改错
      urlField.style.display = 'none';
      urlInput.value = p.baseUrl;
      fmtSel.value = p.apiFormat || 'openai-chat';
      fmtSel.disabled = true;
      fmtHint.textContent = `已根据「${p.name}」自动匹配 API 格式，如需自定义请切换服务商为「自定义」`;
    }

    keyHint.textContent = p.keyHint || '用于身份验证的密钥，本地保存不会上传';
    keyInput.placeholder = p.keyPlaceholder || 'sk-...';

    datalist.innerHTML = p.models.map(id => `<option value="${id}">`).join('');
    if (p.models.length > 0 && !p.models.includes(modelInput.value)) {
      modelInput.value = '';
    }
    modelInput.placeholder = p.models.length > 0 ? '点击下拉选择或输入模型名称' : '输入模型名称';
  }

  function collectAiConfig() {
    return {
      baseUrl: document.getElementById('ai-base-url').value.trim(),
      apiKey: document.getElementById('ai-api-key').value.trim(),
      model: document.getElementById('ai-model').value.trim(),
      maxTokens: parseInt(document.getElementById('ai-max-tokens').value) || 2000,
      temperature: parseFloat(document.getElementById('ai-temperature').value) || 0.7,
      apiFormat: document.getElementById('ai-api-format').value || 'openai-chat'
    };
  }

  async function fetchModels() {
    const btn = document.getElementById('ai-fetch-models-btn');
    const hintEl = document.getElementById('ai-model-hint');
    const inputEl = document.getElementById('ai-model');
    const config = collectAiConfig();

    if (!config.baseUrl || !config.apiKey) {
      hintEl.textContent = '请先填写端点 URL 和 API Key';
      hintEl.style.color = 'var(--destructive)';
      return;
    }

    const originalHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader-2" style="width:14px;height:14px;animation:spin 1s linear infinite;"></i><span>获取中...</span>';
    lucide.createIcons();
    hintEl.textContent = '正在从服务商获取模型列表...';
    hintEl.style.color = 'var(--muted-foreground)';

    try {
      let result;
      if (isElectron && api.aiFetchModels) {
        result = await api.aiFetchModels(config);
      } else {
        // 浏览器模式：直接 fetch
        const isAnthropic = config.baseUrl.toLowerCase().includes('anthropic');
        const baseUrl = config.baseUrl.replace(/\/+$/, '');
        const url = isAnthropic
          ? baseUrl + (baseUrl.includes('/v1') ? '/models' : '/v1/models')
          : baseUrl + '/models';
        const headers = isAnthropic
          ? { 'x-api-key': config.apiKey, 'anthropic-version': '2023-06-01' }
          : { 'Authorization': `Bearer ${config.apiKey}` };
        const res = await fetch(url, { method: 'GET', headers });
        if (!res.ok) {
          let msg = `HTTP ${res.status}`;
          const errText = await res.text();
          try {
            const j = JSON.parse(errText);
            if (j.error?.message) msg += ': ' + j.error.message;
            else if (j.message) msg += ': ' + j.message;
          } catch (_) {
            if (errText) msg += ': ' + errText.slice(0, 200);
          }
          result = { success: false, error: msg };
        } else {
          const j = await res.json();
          let list = [];
          if (Array.isArray(j.data)) list = j.data.map(m => m.id || m.name).filter(Boolean);
          else if (Array.isArray(j.models)) list = j.models.map(m => typeof m === 'string' ? m : (m.id || m.name)).filter(Boolean);
          else if (Array.isArray(j)) list = j.map(m => typeof m === 'string' ? m : (m.id || m.name)).filter(Boolean);
          result = { success: true, models: list.sort() };
        }
      }

      if (result.success && result.models && result.models.length > 0) {
        // 填充 datalist
        const datalist = document.getElementById('ai-model-list');
        datalist.innerHTML = result.models.map(id => `<option value="${id}">`).join('');
        hintEl.textContent = `成功获取 ${result.models.length} 个可用模型，点击输入框下拉选择`;
        hintEl.style.color = 'var(--primary)';
        // 如果当前输入框为空，自动选第一个
        if (!inputEl.value && result.models.length > 0) {
          inputEl.value = result.models[0];
        }
        // 自动展开下拉（聚焦）
        inputEl.focus();
        inputEl.click();
      } else if (result.success && (!result.models || result.models.length === 0)) {
        hintEl.textContent = '服务商返回了空模型列表';
        hintEl.style.color = 'var(--destructive)';
      } else {
        hintEl.textContent = '获取失败：' + (result.error || '未知错误');
        hintEl.style.color = 'var(--destructive)';
      }
    } catch (e) {
      hintEl.textContent = '获取失败：' + e.message;
      hintEl.style.color = 'var(--destructive)';
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalHTML;
      lucide.createIcons();
    }
  }

  async function testAiConnection() {
    const statusEl = document.getElementById('ai-config-status');
    const btn = document.getElementById('ai-test-btn');
    const config = collectAiConfig();
    if (!config.baseUrl || !config.apiKey || !config.model) {
      statusEl.textContent = '请填写完整：端点、API Key、模型名称';
      statusEl.className = 'ai-config-status err';
      return;
    }
    statusEl.textContent = '正在测试连接...';
    statusEl.className = 'ai-config-status testing';
    btn.disabled = true;
    try {
      let result;
      if (isElectron && api.aiTestConnection) {
        result = await api.aiTestConnection(config);
      } else {
        // 浏览器预览：模拟
        await new Promise(r => setTimeout(r, 1200));
        if (/^https?:\/\/.+/i.test(config.baseUrl) && /^sk-.+/.test(config.apiKey) && config.model.length > 2) {
          result = { success: true, status: 200 };
        } else {
          result = { success: false, error: '参数格式不正确（预览模式）' };
        }
      }
      if (result.success) {
        statusEl.innerHTML = '<i data-lucide="check-circle" style="width:12px;height:12px;"></i> 连接成功';
        statusEl.className = 'ai-config-status ok';
      } else {
        statusEl.textContent = '失败：' + (result.error || '未知错误');
        statusEl.className = 'ai-config-status err';
      }
    } catch (e) {
      statusEl.textContent = '失败：' + e.message;
      statusEl.className = 'ai-config-status err';
    } finally {
      btn.disabled = false;
      lucide.createIcons();
    }
  }

  async function saveAiConfig() {
    const statusEl = document.getElementById('ai-config-status');
    const config = collectAiConfig();
    if (!config.baseUrl || !config.apiKey || !config.model) {
      statusEl.textContent = '请填写完整：端点、API Key、模型名称';
      statusEl.className = 'ai-config-status err';
      return;
    }
    try {
      let saved = false;
      if (isElectron && api.aiSaveConfig) {
        const r = await api.aiSaveConfig(config);
        saved = !!r.success;
      } else {
        localStorage.setItem(AI_CFG_LS_KEY, JSON.stringify(config));
        saved = true;
      }
      if (saved) {
        aiConfigCache = config;
        showToast('AI 配置已保存');
        closeAiConfig();
      } else {
        statusEl.textContent = '保存失败';
        statusEl.className = 'ai-config-status err';
      }
    } catch (e) {
      statusEl.textContent = '保存失败：' + e.message;
      statusEl.className = 'ai-config-status err';
    }
  }

  // 简易 Markdown 渲染（仅支持标题、列表、粗体、段落）
  function renderMarkdown(md) {
    let html = md;
    // 转义 HTML
    html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    // 先处理 Markdown 表格（在列表处理之前，避免表格行被识别成列表项）
    html = renderMarkdownTables(html);
    // 标题
    html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    // 粗体
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // 行内代码
    html = html.replace(/`(.+?)`/g, '<code>$1</code>');
    // 分割线
    html = html.replace(/^\s*---+\s*$/gm, '<hr/>');
    // 无序列表
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    html = html.replace(/<\/li>\s*<li>/g, '</li><li>');
    // 有序列表
    html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
    // 段落
    html = html.replace(/\n\n/g, '</p><p>');
    html = '<p>' + html + '</p>';
    // 清理空段落
    html = html.replace(/<p>\s*<\/p>/g, '');
    html = html.replace(/<p>(<h[234]>)/g, '$1');
    html = html.replace(/(<\/h[234]>)<\/p>/g, '$1');
    html = html.replace(/<p>(<ul>)/g, '$1');
    html = html.replace(/(<\/ul>)<\/p>/g, '$1');
    html = html.replace(/<p>(<li>)/g, '<ul>$1');
    html = html.replace(/(<\/li>)<\/p>/g, '$1</ul>');
    // 表格清理（表格行外的 <p></p>）
    html = html.replace(/<p>(<table)/g, '$1');
    html = html.replace(/(<\/table>)<\/p>/g, '$1');
    return html;
  }

  // 简易 Markdown 表格解析器
  function renderMarkdownTables(md) {
    // 匹配格式：| col1 | col2 |\n|---|---|\n| v1 | v2 |
    const tableRegex = /(?:^\s*\|[^\n]+\|\s*\n)(?:^\s*\|[\s\-:]+\|\s*\n)?(?:^\s*\|[^\n]+\|\s*\n)+/gm;
    return md.replace(tableRegex, (tableBlock) => {
      const lines = tableBlock.split('\n').filter(l => l.trim().startsWith('|'));
      if (lines.length < 2) return tableBlock;
      const headerLine = lines[0];
      const dataLines = lines.slice(1).filter(l => !/^\s*\|[\s\-:]+\|\s*$/.test(l));
      const parseRow = (line) => line.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map(c => c.trim());
      const headers = parseRow(headerLine);
      const rows = dataLines.map(parseRow);
      let html = '<table class="md-table">';
      html += '<thead><tr>';
      headers.forEach(h => { html += '<th>' + h + '</th>'; });
      html += '</tr></thead>';
      if (rows.length) {
        html += '<tbody>';
        rows.forEach(row => {
          html += '<tr>';
          const n = Math.max(row.length, headers.length);
          for (let i = 0; i < n; i++) { html += '<td>' + (row[i] || '') + '</td>'; }
          html += '</tr>';
        });
        html += '</tbody>';
      }
      html += '</table>';
      return html;
    });
  }

  // 构建 AI 分析的 prompt
  function buildAiPrompt(device, scanContext, analysisType) {
    const svcs = (device.services || []).map(s => {
      const port = typeof s === 'object' ? s.port : s;
      const name = typeof s === 'object' ? s.name : (PORT_SERVICES[port] || '未知');
      const risk = typeof s === 'object' ? s.risk : 'low';
      const desc = typeof s === 'object' ? (s.desc || '') : (PORT_DESCRIPTIONS[port] || '');
      return `  - 端口 ${port} (${name})，风险等级: ${risk === 'high' ? '高危' : risk === 'medium' ? '中危' : '低危'}${desc ? '，' + desc : ''}`;
    }).join('\n') || '  - 无开放端口';

    const alerts = (scanContext?.alerts || []).map(a => `  - [${a.level === 'high' ? '高危' : '中危'}] ${a.title}: ${a.detail || ''}`).join('\n') || '  - 无告警';

    const deviceInfo = `## 设备信息
- IP 地址: ${device.ip}
- MAC 地址: ${device.mac || '未知'}
- 主机名: ${device.hostname || '未知'}
- 设备类型/分类: ${device.type || '未知'} / ${device.category || 'unknown'}
- 网络状态: ${device.status || '未知'}，延迟 ${device.latency != null ? device.latency + 'ms' : '未知'}，探测方式 ${device.method || '未知'}
- 所属网段: ${scanContext?.cidr || '未知'}
- 本机 IP: ${localInfo?.ip || '未知'}，网关: ${localInfo?.gateway || '未知'}

## 开放端口
${svcs}

## 安全告警
${alerts}`;

    if (analysisType === 'profile') {
      return `你是一位资深网络安全分析师。请根据以下局域网扫描设备信息，生成一份结构详尽的"用户画像分析报告"。

${deviceInfo}

## 输出要求
请用中文，按以下 Markdown 格式输出（不要输出其他内容，每个小节必须完整输出）：

### 使用者身份推测
推测该设备的使用者身份（如高级管理员、系统运维、开发人员、普通员工、IoT 设备拥有者、访客、潜在攻击者等），给出 2-4 条具体判断依据。

### 技能与水平评估
从网络操作、应用部署、安全意识三个维度评估使用者的技术水平（高/中/低），每一项给出具体判断理由。

### 使用目的分析
分析该设备的主要使用目的（如日常办公、开发调试、运维管理、监控采集、文件共享、对外服务等），给出依据。

### 设备归属与管理关系
推测该设备在网络中的角色（终端/服务器/网关/中间件/IoT），以及使用者与设备的可能管理关系（自用/运维他人/共享）。`;
    }

    if (analysisType === 'security') {
      return `你是一位资深网络安全分析师。请根据以下局域网扫描设备信息，生成一份结构详尽的"安全风险分析报告"。

${deviceInfo}

## 输出要求
请用中文，按以下 Markdown 格式输出（不要输出其他内容，每个小节必须完整输出）：

### 风险总评
用一句话给出整体安全风险等级（严重/高/中/低），并用 3-5 条具体数据支撑。

### 端口风险明细表
用 Markdown 表格形式列出所有开放端口的风险：列包括「端口」「服务」「风险等级」「风险说明」「攻击方式」。

### 暴露面与攻击路径
分析该设备的外部暴露面，列出 2-3 条可能的攻击路径（从外部攻击者视角，说明每一步如何利用现有端口/服务渗透进来）。

### 加固优先级建议
按紧急程度从高到低排列 5 条具体可操作的加固建议，每条建议标注预期收益（高/中/低）。`;
    }

    // full —— 综合分析
    return `你是一位资深网络安全分析师。请根据以下局域网扫描设备信息，生成一份结构详尽的"设备 AI 综合分析报告"。

${deviceInfo}

## 输出要求
请用中文，按以下 Markdown 格式输出（不要输出其他内容，每个小节必须完整输出）：

### 一、使用者画像
#### 身份推测
推测该设备的使用者身份，给出 2-4 条具体判断依据。
#### 技能与水平评估
从网络操作、应用部署、安全意识三个维度评估使用者的技术水平，每一项给出具体判断理由。
#### 使用目的
分析该设备的主要使用目的，给出依据。
#### 设备角色
推测该设备在网络拓扑中的角色（终端/服务器/网关/中间件/IoT/摄像头/打印机等）。

### 二、安全风险评估
#### 风险总评
用一句话给出整体安全风险等级（严重/高/中/低），并用 3-5 条具体数据支撑。
#### 端口风险明细表
用 Markdown 表格形式列出所有开放端口的风险：列包括「端口」「服务」「风险等级」「风险说明」。
#### 暴露面分析
分析该设备的外部暴露面（端口数量、协议类型、对外服务性质）。

### 三、攻击路径推演
按以下时间线结构，列出 3-5 条可能的攻击路径：
- 第一步：攻击者通过 XX 入口进入（如端口扫描、弱口令、未授权服务等）
- 第二步：利用 XX 漏洞/服务做什么
- 第三步：最终获取 XX 权限或数据

### 四、加固建议
按紧急程度从高到低排列 5-7 条具体可操作的加固建议。

### 五、总结
用 2-3 句话总结该设备的核心安全状况。`;
  }

  // 多字段兼容解析：适配各种 OpenAI 兼容中间件（OneAPI/NewAPI/国内代理等）
  function extractChoiceText(json) {
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
  }

  // 根据 apiFormat 构造请求（浏览器 + Electron 共用逻辑）
  function buildAiRequest(cfg, systemPrompt, userPrompt, stream) {
    const format = cfg.apiFormat || 'openai-chat';
    const baseUrl = cfg.baseUrl.replace(/\/+$/, '');
    const sysMsg = systemPrompt;
    const usrMsg = userPrompt;
    const maxT = cfg.maxTokens || 2000;
    const temp = cfg.temperature || 0.7;

    switch (format) {
      case 'anthropic-messages': {
        const url = baseUrl + (baseUrl.includes('/v1') ? '/messages' : '/v1/messages');
        return {
          url,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': cfg.apiKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: cfg.model,
            system: sysMsg,
            messages: [{ role: 'user', content: usrMsg }],
            max_tokens: Math.min(maxT, 8192),
            temperature: temp,
            stream: !!stream
          }),
          format: 'anthropic-messages'
        };
      }
      case 'openai-responses': {
        const url = baseUrl + (baseUrl.includes('/v1') ? '/responses' : '/v1/responses');
        return {
          url,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${cfg.apiKey}`
          },
          body: JSON.stringify({
            model: cfg.model,
            instructions: sysMsg,
            input: [{ role: 'user', content: [{ type: 'input_text', text: usrMsg }] }],
            temperature: temp,
            max_output_tokens: Math.min(maxT, 8192),
            stream: !!stream
          }),
          format: 'openai-responses'
        };
      }
      case 'openai-completions': {
        const url = baseUrl + (baseUrl.includes('/v1') ? '/completions' : '/v1/completions');
        return {
          url,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${cfg.apiKey}`
          },
          body: JSON.stringify({
            model: cfg.model,
            prompt: `${sysMsg}\n\n用户：${usrMsg}\n助理：`,
            suffix: null,
            temperature: temp,
            max_tokens: Math.min(maxT, 8192),
            stream: !!stream
          }),
          format: 'openai-completions'
        };
      }
      case 'gemini': {
        const url = `${baseUrl}/models/${cfg.model}:${stream ? 'streamGenerateContent' : 'generateContent'}?key=${encodeURIComponent(cfg.apiKey)}`;
        return {
          url,
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: sysMsg }] },
            contents: [{ role: 'user', parts: [{ text: usrMsg }] }],
            generationConfig: { temperature: temp, maxOutputTokens: Math.min(maxT, 8192) }
          }),
          format: 'gemini'
        };
      }
      case 'ollama-chat': {
        const url = baseUrl + '/api/chat';
        return {
          url,
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: cfg.model,
            messages: [
              { role: 'system', content: sysMsg },
              { role: 'user', content: usrMsg }
            ],
            options: { temperature: temp, num_predict: Math.min(maxT, 8192) },
            stream: !!stream
          }),
          format: 'ollama-chat'
        };
      }
      case 'openai-chat':
      default: {
        const url = baseUrl + '/chat/completions';
        return {
          url,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${cfg.apiKey}`
          },
          body: JSON.stringify({
            model: cfg.model,
            messages: [
              { role: 'system', content: sysMsg },
              { role: 'user', content: usrMsg }
            ],
            max_tokens: Math.min(maxT, 8192),
            temperature: temp,
            stream: !!stream
          }),
          format: 'openai-chat'
        };
      }
    }
  }

  // 从任意格式的 JSON chunk 中提取文本增量
  function extractDeltaFromJson(json, format) {
    // 优先用通用 extractChoiceText
    const g = extractChoiceText(json);
    if (g) return g;
    // 各格式专属兜底
    if (!format || format === 'openai-chat' || format === 'openai-responses' || format === 'openai-completions') return null;
    if (format === 'ollama-chat') {
      if (json?.message?.content) return json.message.content;
    }
    if (format === 'gemini') {
      // stream: candidates[0].content.parts[0].text / non-stream: same
      const c = json?.candidates?.[0];
      if (c?.content?.parts?.[0]?.text) return c.content.parts[0].text;
      if (c?.output) return c.output;
    }
    return null;
  }

  // 浏览器模式：直接用 fetch 调用 AI API（支持流式 + Abort 超时 + 非流式回退）
  async function fetchAiAnalysis(cfg, device, scanContext, onChunk, timeoutMs = 60000, analysisType = 'full') {
    const systemPrompt = '你是一位专业的网络安全分析师，擅长分析局域网设备的安全风险。请使用中文回答，输出 Markdown 格式。';
    const userPrompt = buildAiPrompt(device, scanContext, analysisType);
    const req = buildAiRequest(cfg, systemPrompt, userPrompt, true);

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = setTimeout(() => controller && controller.abort(), timeoutMs);
    const signal = controller ? controller.signal : undefined;

    try {
      const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, signal });
      clearTimeout(timer);
      if (!res.ok) {
        const errText = await res.text();
        let msg = `HTTP ${res.status}`;
        try {
          const j = JSON.parse(errText);
          if (j.error?.message) msg += ': ' + j.error.message;
          else if (j.message) msg += ': ' + j.message;
          else if (j.msg) msg += ': ' + j.msg;
        } catch (_) {
          if (errText) msg += ': ' + errText.slice(0, 300);
        }
        return { success: false, error: msg };
      }
      if (!res.body || typeof res.body.getReader !== 'function') {
        const text = await res.text();
        try {
          const j = JSON.parse(text);
          const content = extractChoiceText(j) || extractDeltaFromJson(j, req.format);
          if (content) return { success: true, content };
        } catch (_) { /* not JSON */ }
        return { success: false, error: '服务器未返回可读内容（长度 ' + text.length + '）' };
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let fullText = '';
      let streamEmpty = true;
      let rawBody = '';
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const str = decoder.decode(value, { stream: true });
        rawBody += str;
        buffer += str;
        // gemini/ollama 可能每行一个 JSON，没有 data: 前缀；OpenAI/Anthropic 有 data:
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          // 1) 标准 SSE data: 前缀
          let dataStr = trimmed;
          if (trimmed.startsWith('data: ')) {
            dataStr = trimmed.slice(6);
            if (dataStr === '[DONE]') continue;
          } else if (trimmed.startsWith(': ')) {
            continue; // 心跳/注释
          }
          try {
            const json = JSON.parse(dataStr);
            // ollama 的 done: true 标记
            if (req.format === 'ollama-chat' && json?.done === true) continue;
            const delta = extractDeltaFromJson(json, req.format);
            if (delta) {
              streamEmpty = false;
              fullText += delta;
              if (onChunk) onChunk(delta);
            }
          } catch (e) { /* skip invalid JSON */ }
        }
      }

      // 如果流式解析不出内容，尝试把全部响应拼接/整体解析
      if (streamEmpty && rawBody.trim()) {
        try {
          let cleaned = rawBody;
          if (cleaned.includes('data: ')) {
            cleaned = cleaned
              .split('\n')
              .map(l => l.trim())
              .filter(l => l.startsWith('data: ') && l.slice(6) !== '[DONE]')
              .map(l => l.slice(6))
              .join('');
          }
          if (cleaned) {
            const j = JSON.parse(cleaned);
            const txt = extractChoiceText(j);
            if (txt) fullText = txt;
          }
          if (!fullText) {
            try {
              const rawJ = JSON.parse(rawBody);
              const txt = extractChoiceText(rawJ);
              if (txt) fullText = txt;
            } catch (_) { /* not JSON */ }
          }
        } catch (_) { /* ignore */ }
      }

      // 终极 fallback：再次非流式请求（关闭 stream）
      if (!fullText) {
        try {
          const nonStreamReq = buildAiRequest(cfg, systemPrompt, userPrompt, false);
          const ctrl2 = typeof AbortController !== 'undefined' ? new AbortController() : null;
          const t2 = setTimeout(() => ctrl2 && ctrl2.abort(), 45000);
          const res2 = await fetch(nonStreamReq.url, {
            method: nonStreamReq.method,
            headers: nonStreamReq.headers,
            body: nonStreamReq.body,
            signal: ctrl2 ? ctrl2.signal : undefined
          });
          clearTimeout(t2);
          if (res2.ok) {
            const text2 = await res2.text();
            try {
              const j2 = JSON.parse(text2);
              const txt2 = extractChoiceText(j2) || extractDeltaFromJson(j2, nonStreamReq.format);
              if (txt2) fullText = txt2;
            } catch (_) { /* not JSON */ }
          }
        } catch (_) { /* ignore fallback */ }
      }

      if (!fullText) return { success: false, error: '响应为空，请尝试更换模型（有些中间件 stream=true 时只推心跳不推内容）' };
      return { success: true, content: fullText };
    } catch (e) {
      if (e && e.name === 'AbortError') return { success: false, error: `请求超时（${timeoutMs / 1000}s），请检查网络或端点` };
      return { success: false, error: e.message || String(e) };
    } finally {
      clearTimeout(timer);
    }
  }

  // Promise 超时包装：防止 ipcRenderer.invoke(未注册事件) 永远 pending
  function withTimeout(promise, ms, msg) {
    let timerId;
    const timeout = new Promise((_, reject) => {
      timerId = setTimeout(() => reject(new Error(msg || `超时（${ms / 1000}s）`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timerId));
  }

  // 切换 AI 分析类型按钮的高亮状态（primary 类）
  function setActiveAiType(type) {
    try {
      document.querySelectorAll('.ai-type-btn').forEach(btn => {
        if (btn.dataset.type === type) {
          btn.classList.add('primary');
        } else {
          btn.classList.remove('primary');
        }
      });
    } catch (_) { /* ignore */ }
  }

  // ── AI 独立全屏报告页 ────────────────────────────────────────
  let aiFullState = { type: 'full', running: false, streamedText: '' };

  // 设备类型中文标签映射
  const DEVICE_CATEGORY_LABELS = {
    router: '路由器/网关',
    computer: '电脑/工作站',
    phone: '手机/移动设备',
    iot: 'IoT 物联网设备',
    camera: '网络摄像头',
    virtual: '虚拟设备',
    printer: '打印机',
    server: '服务器',
    unknown: '未知设备'
  };
  function deviceCategoryLabel(cat) {
    return DEVICE_CATEGORY_LABELS[cat] || cat || '未知设备';
  }

  function enterFullAiPage(type) {
    const page = document.getElementById('ai-full-page');
    if (!page) return;
    if (!currentDetailDevice) {
      showToast('请先选择一个设备');
      return;
    }
    aiFullState.type = type || 'full';
    page.style.display = 'flex';
    setFullAiTypeBtnActive(aiFullState.type);

    // 填充设备信息卡（双栏布局的新 -v2 DOM 是主显示，旧 DOM 被 CSS 隐藏）
    const d = currentDetailDevice;
    const nameEl = document.getElementById('ai-full-device-name-v2');
    const metaEl = document.getElementById('ai-full-device-meta-v2');
    const tagsEl = document.getElementById('ai-full-device-tags-v2');
    const iconEl = document.getElementById('ai-full-device-icon-v2');
    const iconMap = { router: 'router', computer: 'monitor', phone: 'smartphone', iot: 'cpu', camera: 'video', virtual: 'box', unknown: 'help-circle', printer: 'printer', server: 'server' };
    const iconName = iconMap[d.category] || 'server';
    if (iconEl) iconEl.innerHTML = `<i data-lucide="${iconName}"></i>`;
    if (nameEl) nameEl.textContent = d.name || d.hostname || d.ip || '未知设备';
    const metaParts = [d.ip, d.mac].filter(Boolean);
    if (d.vendor) metaParts.push(d.vendor);
    metaParts.push(d.category ? (deviceCategoryLabel(d.category) || d.category) : '未知类型');
    if (metaEl) metaEl.textContent = metaParts.join(' · ');
    // 标签
    const tagList = [];
    if (d.category) tagList.push({ label: deviceCategoryLabel(d.category) || d.category, cls: 'ai-badge-primary' });
    if (d.services && d.services.length) tagList.push({ label: `${d.services.length} 个端口`, cls: 'ai-badge-success' });
    if (d.online === true || d.latency != null) tagList.push({ label: '在线', cls: 'ai-badge-success' });
    const criticalCount = (activeAlerts || []).filter(a => a.ip === d.ip && a.severity === 'high').length;
    if (criticalCount > 0) tagList.push({ label: `${criticalCount} 条高危`, cls: 'ai-badge-error' });
    if (tagsEl) tagsEl.innerHTML = tagList.map(t => `<span class="ai-badge ${t.cls}">${t.label}</span>`).join('');
    // 统计（2x2 grid）
    const portsNum = (d.services || []).length;
    const alertsForDevice = (activeAlerts || []).filter(a => a.ip === d.ip);
    const alertsNum = alertsForDevice.length;
    const cidrVal = selectedAdapter?.cidr || '-';
    const riskLevel = aiFullRiskLevel(alertsNum, portsNum);
    document.getElementById('ai-full-stat-ports-v2').textContent = String(portsNum);
    document.getElementById('ai-full-stat-alerts-v2').textContent = String(alertsNum);
    document.getElementById('ai-full-stat-cidr-v2').textContent = cidrVal;
    const riskElV2 = document.getElementById('ai-full-stat-risk-v2');
    riskElV2.textContent = aiFullRiskText(riskLevel);
    riskElV2.className = 'ai-full-stat-value ai-risk-' + riskLevel;

    // 时间戳
    const timeEl = document.getElementById('ai-full-time');
    if (timeEl) timeEl.textContent = '刚刚';

    // 【左栏端口列表】
    const portListEl = document.getElementById('ai-full-port-list');
    if (portListEl) {
      if (!d.services || d.services.length === 0) {
        portListEl.innerHTML = '<div class="ai-full-port-empty">暂无端口数据</div>';
      } else {
        portListEl.innerHTML = (d.services || []).slice(0, 30).map(s => {
          const port = typeof s === 'object' ? s.port : s;
          const svc = typeof s === 'object' ? (s.name || PORT_SERVICES[port] || '未知') : (PORT_SERVICES[s] || '未知');
          const risk = typeof s === 'object' ? (s.risk || 'low') : 'low';
          const riskCls = risk === 'high' ? 'high' : risk === 'medium' ? 'med' : '';
          const riskText = risk === 'high' ? '高危' : risk === 'medium' ? '中危' : '';
          return `<div class="ai-full-port-item">
            <span class="ai-full-port-num">${port}</span>
            <span class="ai-full-port-svc" title="${svc}">${svc}</span>
            ${riskText ? `<span class="ai-full-port-risk ${riskCls}">${riskText}</span>` : ''}
          </div>`;
        }).join('');
      }
    }

    // 【左栏安全告警列表】
    const alertListEl = document.getElementById('ai-full-alert-list');
    if (alertListEl) {
      if (!alertsForDevice.length) {
        alertListEl.innerHTML = '<div class="ai-full-alert-empty">该设备暂未发现安全告警</div>';
      } else {
        alertListEl.innerHTML = alertsForDevice.map(a => {
          const isWarn = a.severity === 'medium' || a.severity === 'warn';
          return `<div class="ai-full-alert-item ${isWarn ? 'warn' : ''}">
            <div class="ai-full-alert-title">${a.title || a.name || '安全告警'}</div>
            <div class="ai-full-alert-desc">${a.desc || a.detail || ''}</div>
          </div>`;
        }).join('');
      }
    }

    // 绑定左侧快捷操作（防抖 dataset.bound 避免重复绑定）
    bindFullQuickActions(d);

    // 渲染加载态
    renderFullAiLoading(`AI ${aiFullTypeLabel(type)}进行中...`);

    // 绑定顶部按钮（返回 / 重新分析 / 复制）
    const backBtn = document.getElementById('ai-full-back');
    if (backBtn && !backBtn.dataset.bound) {
      backBtn.dataset.bound = '1';
      backBtn.addEventListener('click', exitFullAiPage);
    }
    const regenBtn = document.getElementById('ai-full-regen');
    if (regenBtn && !regenBtn.dataset.bound) {
      regenBtn.dataset.bound = '1';
      regenBtn.addEventListener('click', () => {
        openAiAnalysis(aiFullState.type, { force: true, target: 'full' });
      });
    }
    const copyBtn = document.getElementById('ai-full-copy');
    if (copyBtn && !copyBtn.dataset.bound) {
      copyBtn.dataset.bound = '1';
      copyBtn.addEventListener('click', () => {
        const content = document.getElementById('ai-full-content-v2');
        if (!content) return;
        const body = content.querySelector('.ai-full-content-body') || content;
        const text = body ? body.innerText : '';
        if (!text) { showToast('没有可复制的内容'); return; }
        navigator.clipboard.writeText(text).then(() => showToast('报告已复制到剪贴板'));
      });
    }

    // 图标刷新（左栏 h4 插入了新的 i[data-lucide]）
    try { lucide.createIcons(); } catch (_) {}
  }

  // 绑定左栏快捷操作（只绑一次）
  let fullQuickBound = false;
  function bindFullQuickActions(device) {
    if (fullQuickBound) return;
    fullQuickBound = true;
    // Ping
    const pingBtn = document.getElementById('ai-full-q-ping');
    if (pingBtn) pingBtn.addEventListener('click', async () => {
      if (!device?.ip) return;
      exitFullAiPage();
      // 选中设备，切换到 Ping tab，发起 Ping
      selectDevice(device);
      document.getElementById('tab-ping')?.click();
      const startPingBtn = document.getElementById('btn-ping-start');
      if (startPingBtn) setTimeout(() => startPingBtn.click(), 80);
      showToast(`已切换到 Ping 面板：${device.ip}`);
    });
    // 端口扫描
    const portsBtn = document.getElementById('ai-full-q-ports');
    if (portsBtn) portsBtn.addEventListener('click', async () => {
      if (!device?.ip) return;
      exitFullAiPage();
      selectDevice(device);
      document.getElementById('tab-portscan')?.click();
      const fullBtn = document.getElementById('port-scan-full') ||
        Array.from(document.querySelectorAll('.port-range-btn, #port-scan-all-btn, button[data-range="full"]')).find(b => b.innerText.includes('全端口') || b.innerText.includes('全部'));
      if (fullBtn) setTimeout(() => fullBtn.click(), 80);
      showToast(`已切换到端口扫描面板：${device.ip}`);
    });
    // 重新识别厂商
    const vendorBtn = document.getElementById('ai-full-q-vendor');
    if (vendorBtn) vendorBtn.addEventListener('click', async () => {
      if (!device?.mac && !device?.ip) { showToast('设备信息不全'); return; }
      showToast('正在重新识别设备厂商/OUI...');
      // 若有补证接口则触发；否则提示用户重新发起全量扫描
      if (isElectron && api.enrichDevice) {
        try {
          const r = await api.enrichDevice({ ip: device.ip });
          if (r && r.success && r.device) {
            Object.assign(device, r.device);
            selectDevice(device);
            enterFullAiPage(aiFullState.type);
            showToast('厂商信息已更新');
          } else {
            showToast('未获取到新的厂商信息');
          }
        } catch (_) { showToast('识别失败，请重试'); }
      } else {
        showToast('请关闭后重新扫描以识别厂商');
      }
    });
    // 复制 IP
    const copyIpBtn = document.getElementById('ai-full-q-copy-ip');
    if (copyIpBtn) copyIpBtn.addEventListener('click', () => {
      if (!device?.ip) return;
      navigator.clipboard.writeText(device.ip).then(() => showToast(`IP ${device.ip} 已复制`));
    });
    // 返回设备详情
    const closeBtn = document.getElementById('ai-full-q-close-detail');
    if (closeBtn) closeBtn.addEventListener('click', () => {
      exitFullAiPage();
      showToast('已返回设备详情');
    });
  }

  function exitFullAiPage() {
    const page = document.getElementById('ai-full-page');
    if (page) page.style.display = 'none';
  }

  function aiFullTypeLabel(type) {
    return { profile: '用户画像分析', security: '安全风险分析', full: '综合分析' }[type] || '综合分析';
  }

  function aiFullRiskLevel(alerts, ports) {
    if (alerts >= 3) return 'critical';
    if (alerts >= 1 || ports >= 10) return 'high';
    if (ports >= 5) return 'medium';
    return 'low';
  }

  function aiFullRiskText(level) {
    return { low: '低风险', medium: '中等风险', high: '高风险', critical: '严重风险' }[level] || '-';
  }

  function renderFullAiLoading(title) {
    const c = document.getElementById('ai-full-content-v2') || document.getElementById('ai-full-content');
    if (!c) return;
    c.innerHTML = `
      <div class="ai-full-loading">
        <div class="ai-full-loading-title"><span class="dot"></span> ${title}</div>
        <div class="ai-full-loading-meta" id="ai-full-loading-meta-v2">正在建立连接并构造请求...</div>
        <div class="ai-full-loading-bar"><div class="ai-full-loading-bar-inner"></div></div>
      </div>`;
    try { lucide.createIcons(); } catch (_) {}
  }

  function renderFullAiResult(type, text, riskLevel) {
    const c = document.getElementById('ai-full-content-v2') || document.getElementById('ai-full-content');
    if (!c) return;
    const typeLabel = aiFullTypeLabel(type);
    const level = riskLevel || 'low';
    const badge = `<span class="ai-full-risk-badge ${level}">${aiFullRiskText(level)}</span>`;
    c.innerHTML =
      `<div class="ai-full-result-header">
         <div class="ai-full-result-title"><i data-lucide="sparkles"></i> AI ${typeLabel}报告</div>
         ${badge}
       </div>` +
      `<div class="ai-full-content-body">${renderMarkdown(text)}</div>`;
    try { lucide.createIcons(); } catch (_) {}
  }

  function renderFullAiError(errMsg) {
    const c = document.getElementById('ai-full-content-v2') || document.getElementById('ai-full-content');
    if (!c) return;
    c.innerHTML = `<div class="ai-full-error">
      <i data-lucide="alert-triangle" style="width:20px;height:20px;"></i><br/>
      <b style="margin-top:8px;display:inline-block;">分析失败</b>
      <div style="margin-top:10px;word-break:break-all;">${errMsg || '未知错误'}</div>
    </div>`;
    try { lucide.createIcons(); } catch (_) {}
  }

  // 将 AI 流式 chunk 追加到全屏页的结果区（供 runAiAnalysis 调用）
  function appendFullAiChunk(chunk) {
    const c = document.getElementById('ai-full-content-v2') || document.getElementById('ai-full-content');
    if (!c) return;
    if (!aiFullState.streamedText) {
      // 首次 chunk：切换到流式输出状态，显示基础框架
      aiFullState.streamedText = '';
      const typeLabel = aiFullTypeLabel(aiFullState.type);
      c.innerHTML =
        `<div class="ai-full-result-header">
           <div class="ai-full-result-title"><i data-lucide="sparkles"></i> AI ${typeLabel}报告</div>
           <span class="ai-full-risk-badge low">生成中</span>
         </div>` +
        `<div class="ai-full-content-body" id="ai-full-stream-body"></div>`;
      try { lucide.createIcons(); } catch (_) {}
    }
    aiFullState.streamedText += chunk;
    const body = document.getElementById('ai-full-stream-body');
    if (body) {
      body.innerHTML = renderMarkdown(aiFullState.streamedText);
    } else {
      // body 不存在（可能已被替换成最终版本），不追加
    }
  }

  async function runAiAnalysis(analysisType) {
    analysisType = analysisType || 'full';
    // 进入时立即同步高亮（保证无论从哪个入口调用都一致）
    setActiveAiType(analysisType);
    if (aiAnalyzing) return;
    if (!currentDetailDevice) {
      showToast('请先选择一个设备');
      return;
    }

    const cfg = await loadAiConfig();
    const configured = !!(cfg && cfg.apiKey && cfg.baseUrl && cfg.model);
    if (!configured) {
      showToast('请先配置 AI 模型');
      openAiConfig();
      return;
    }

    aiAnalyzing = true;
    const resultEl = document.getElementById('ai-result');
    const typeBtns = document.querySelectorAll('.ai-type-btn');
    const fullTypeBtns = document.querySelectorAll('.ai-full-type-switch .ai-full-btn');
    const fullRegenBtn = document.getElementById('ai-full-regen');
    const typeLabels = { profile: '用户画像分析', security: '安全风险分析', full: '综合分析' };
    const fullPage = document.getElementById('ai-full-page');
    const isFullPageVisible = !!(fullPage && fullPage.style.display !== 'none');

    // 禁用所有按钮（侧栏类型按钮 + 全屏页类型切换/重新分析按钮）
    typeBtns.forEach(b => b.disabled = true);
    fullTypeBtns.forEach(b => b.disabled = true);
    if (fullRegenBtn) fullRegenBtn.disabled = true;

    // 加载状态（支持 meta 局部替换或整体重渲染）
    let loadingMetaNode = null;
    const renderLoading = (stepText) => {
      resultEl.innerHTML = `
        <div class="ai-loading">
          <div class="ai-loading-header"><div class="dot"></div> AI ${typeLabels[analysisType]} 进行中...</div>
          <div class="ai-loading-meta">${stepText}</div>
          <div class="ai-loading-bar"><div class="ai-loading-bar-inner"></div></div>
        </div>`;
      loadingMetaNode = resultEl.querySelector('.ai-loading-meta');
    };
    // 仅更新等待计时的秒数（不重新渲染整个 loading 容器，避免动画闪烁）
    const updateLoadingElapsed = (secText) => {
      if (loadingMetaNode && loadingMetaNode.isConnected) {
        loadingMetaNode.dataset.elapsed = secText;
        loadingMetaNode.textContent = loadingMetaNode.textContent.replace(/等待响应 \([0-9.]+s\)/, `等待响应 (${secText}s)`);
      }
      // 同步更新全屏页 loading 上的等待计时
      const fullMeta = document.getElementById('ai-full-loading-meta-v2');
      if (fullMeta) {
        fullMeta.dataset.elapsed = secText;
        if (fullMeta.textContent.includes('等待响应')) {
          fullMeta.textContent = fullMeta.textContent.replace(/等待响应[^\n]*/, `等待响应 · ${secText}s`);
        } else {
          fullMeta.textContent = `模型请求中 · 等待响应 (${secText}s)`;
        }
      }
    };
    let loadingTimer = null;
    const stopLoadingTimer = () => {
      if (loadingTimer) { clearInterval(loadingTimer); loadingTimer = null; }
    };

    try {
      const deviceAlerts = activeAlerts.filter(a => a.ip === currentDetailDevice.ip);
      const scanContext = {
        cidr: selectedAdapter?.cidr || '-',
        alerts: deviceAlerts
      };
      const modeName = (isElectron && api.aiAnalyzeDevice) ? 'Electron IPC' : '浏览器 Fetch';
      renderLoading(`环境: ${modeName} ｜ 模型: ${cfg.model} ｜ 正在发送请求...`);

      let streamedText = '';
      const appendChunk = (chunk) => {
        // 第一块内容到达：停止等待计时，进入"正在输出"状态
        if (!streamedText) stopLoadingTimer();
        streamedText += chunk;
        resultEl.innerHTML =
          '<div class="ai-result-toolbar">' +
            '<span class="ai-result-label"><i data-lucide="sparkles" style="width:12px;height:12px;"></i> AI 正在输出</span>' +
          '</div>' +
          '<div class="ai-analysis-content">' + renderMarkdown(streamedText) + '</div>';
        resultEl.scrollTop = resultEl.scrollHeight;
        // 全屏页可见时，同步追加流式 chunk
        if (isFullPageVisible) {
          aiFullState.streamedText = streamedText;
          appendFullAiChunk(chunk);
        }
      };

      // 清理 + 重新挂接 Electron 流式监听
      if (aiStreamCleanup) { try { aiStreamCleanup(); } catch (_) {} aiStreamCleanup = null; }
      if (isElectron && api.onAiStreamChunk) {
        aiStreamCleanup = api.onAiStreamChunk(appendChunk);
      }

      let result;
      const startedAt = Date.now();
      // 每 100ms 刷新一次"等待响应 (X.Xs)"，给用户明确的进度感知
      const tickElapsed = () => {
        updateLoadingElapsed(((Date.now() - startedAt) / 1000).toFixed(1));
      };

      if (isElectron && api.aiAnalyzeDevice) {
        renderLoading(`环境: ${modeName} ｜ 模型: ${cfg.model} ｜ 等待响应 (0.0s)...`);
        loadingTimer = setInterval(tickElapsed, 100);
        try {
          result = await withTimeout(
            api.aiAnalyzeDevice({
              device: currentDetailDevice,
              localInfo: localInfo,
              scanContext: scanContext,
              analysisType: analysisType
            }),
            75000,
            'AI 调用超时（75s），请检查网络或重启程序后重试'
          );
        } catch (ipcErr) {
          result = { success: false, error: ipcErr.message || String(ipcErr) };
        }
      } else if (!isElectron && !window.fetch) {
        result = { success: false, error: '当前环境不支持 fetch，请使用 Electron 打开本程序' };
      } else {
        renderLoading(`环境: ${modeName} ｜ 端点: ${cfg.baseUrl.replace(/\/+$/, '')} ｜ 等待响应 (0.0s)...`);
        loadingTimer = setInterval(tickElapsed, 100);
        result = await fetchAiAnalysis(cfg, currentDetailDevice, scanContext, appendChunk, 75000, analysisType);
      }

      if (aiStreamCleanup) { try { aiStreamCleanup(); } catch (_) {} aiStreamCleanup = null; }

      const finalText = result.content || streamedText;

      if (result.success && finalText && finalText.trim().length > 0) {
        const html = renderMarkdown(finalText);
        const portsNum = (currentDetailDevice?.ports || []).length;
        const alertsNum = (activeAlerts || []).filter(a => a.ip === currentDetailDevice?.ip).length;
        const riskLevel = aiFullRiskLevel(alertsNum, portsNum);
        // 写入缓存：按设备 IP + 分析类型
        setCachedAiResult(analysisType, { text: finalText, time: Date.now(), riskLevel });
        // 保存最近一次分析结果，供「展开全屏查看」按钮使用
        window.__aiLastResult = { type: analysisType, text: finalText, time: Date.now() };
        resultEl.innerHTML =
          '<div class="ai-result-toolbar">' +
            '<span class="ai-result-label"><i data-lucide="check-circle" style="width:12px;height:12px;color:var(--scanner-state-success);"></i> ' + typeLabels[analysisType] + ' · 已完成</span>' +
            '<div class="ai-result-actions">' +
              '<button class="ai-result-btn" id="ai-fullscreen-btn"><i data-lucide="maximize-2" style="width:11px;height:11px;"></i> 展开查看</button>' +
              '<button class="ai-result-btn" id="ai-copy-btn"><i data-lucide="copy" style="width:11px;height:11px;"></i> 复制</button>' +
              '<button class="ai-result-btn" id="ai-retry-btn"><i data-lucide="refresh-cw" style="width:11px;height:11px;"></i> 重新分析</button>' +
            '</div>' +
          '</div>' +
          '<div class="ai-analysis-content">' + html + '</div>';
        // 绑定复制、重新分析、展开全屏
        document.getElementById('ai-copy-btn')?.addEventListener('click', () => {
          navigator.clipboard.writeText(finalText).then(() => showToast('已复制到剪贴板'));
        });
        document.getElementById('ai-retry-btn')?.addEventListener('click', () => openAiAnalysis(analysisType, { force: true }));
        document.getElementById('ai-fullscreen-btn')?.addEventListener('click', () => {
          enterFullAiPage(analysisType);
          const last = window.__aiLastResult;
          if (last && last.type === analysisType) {
            const portsNum = (currentDetailDevice?.ports || []).length;
            const alertsNum = (activeAlerts || []).filter(a => a.ip === currentDetailDevice?.ip).length;
            const riskLevel = aiFullRiskLevel(alertsNum, portsNum);
            renderFullAiResult(analysisType, last.text, riskLevel);
            const tEl = document.getElementById('ai-full-time');
            if (tEl) tEl.textContent = '刚刚';
          }
          try { lucide.createIcons(); } catch (_) {}
        });
        // 全屏页可见时，同步渲染最终结果
        if (isFullPageVisible) {
          const portsNum = (currentDetailDevice?.ports || []).length;
          const alertsNum = (activeAlerts || []).filter(a => a.ip === currentDetailDevice?.ip).length;
          const riskLevel = aiFullRiskLevel(alertsNum, portsNum);
          renderFullAiResult(analysisType, finalText, riskLevel);
          const tEl = document.getElementById('ai-full-time');
          if (tEl) tEl.textContent = '刚刚';
          try { lucide.createIcons(); } catch (_) {}
        }
      } else {
        resultEl.innerHTML =
          '<div class="ai-analysis-error">' +
          '<i data-lucide="alert-triangle" style="width:14px;height:14px;vertical-align:-2px;"></i> ' +
          '<b>分析失败</b>' +
          '<div style="margin-top:8px;line-height:1.7;word-break:break-all;">' +
          (result.error || 'AI 返回内容为空，请检查模型配置或更换模型') +
          '</div></div>';
        // 全屏页可见时，同步渲染错误
        if (isFullPageVisible) {
          renderFullAiError(result.error || 'AI 返回内容为空，请检查模型配置或更换模型');
        }
      }
      lucide.createIcons();
    } catch (e) {
      if (aiStreamCleanup) { try { aiStreamCleanup(); } catch (_) {} aiStreamCleanup = null; }
      resultEl.innerHTML =
        '<div class="ai-analysis-error">' +
        '<b>分析异常</b>' +
        '<div style="margin-top:8px;line-height:1.7;">' + (e && e.message ? e.message : String(e)) + '</div>' +
        '</div>';
      // 全屏页可见时，同步渲染异常
      if (isFullPageVisible) {
        renderFullAiError(e && e.message ? e.message : String(e));
      }
      lucide.createIcons();
    } finally {
      stopLoadingTimer();
      aiAnalyzing = false;
      typeBtns.forEach(b => b.disabled = false);
      fullTypeBtns.forEach(b => b.disabled = false);
      if (fullRegenBtn) fullRegenBtn.disabled = false;
    }
  }

  // 浏览器预览用的 mock AI 分析，同时模拟流式输出
  async function mockAiAnalysis(device, scanContext, onChunk) {
    const catLabel = { phone: '手机/移动设备', computer: '电脑/工作站', router: '路由器/网关', iot: 'IoT 物联网设备', camera: '网络摄像头', virtual: '虚拟设备', unknown: '未知设备' }[device.category] || '局域网设备';
    const svcCount = (device.services || []).length;
    const highRisk = (device.services || []).filter(s => s.risk === 'high').length;
    const latency = device.latency != null ? device.latency + 'ms' : '未知';

    let usageText;
    if (catLabel.includes('手机')) usageText = '典型的终端移动设备，通常由个人日常使用，可能属于办公人员或家庭用户。\n\n';
    else if (catLabel.includes('电脑')) usageText = '桌面/笔记本工作站，常见于员工办公台，可能涉及内部文档、邮件、开发工具等敏感数据。\n\n';
    else if (catLabel.includes('路由')) usageText = '网络基础设施节点，承担 NAT、DHCP、路由转发等核心功能，一旦被攻陷将影响整个网段。\n\n';
    else if (catLabel.includes('摄像')) usageText = '视频监控类设备，通常部署在办公/生产/门禁场景，视频数据涉及隐私合规。\n\n';
    else if (catLabel.includes('IoT')) usageText = '物联网终端（打印机/门禁/传感器等），安全固件更新滞后，易成为横向移动跳板。\n\n';
    else usageText = '网络终端设备，需要进一步结合开放端口和主机名判断场景。\n\n';

    let svcText;
    if (svcCount === 0) svcText = '无开放端口，若为个人终端属于正常桌面防护水平；若为基础设施则需警惕是否被异常关闭。\n\n';
    else if (highRisk > 0) svcText = '存在高危暴露端口（Telnet/SMB/RDP 等），可能使用人群偏技术向或运维管理员，但安全意识有待提升。\n\n';
    else svcText = '仅开放常规 HTTP/HTTPS，符合普通终端或轻量 Web 服务设备画像。\n\n';

    let portRiskText;
    if (svcCount > 0) portRiskText = '建议逐项复核业务必要性，非必须端口应通过 ACL / 防火墙关闭。\n\n';
    else portRiskText = '目前无明显服务暴露，建议定期复查避免后台服务被静默开启。\n\n';

    let protoText;
    if ((device.services || []).some(s => s.port === 23)) protoText = '检测到 **Telnet(23)** 明文协议，极易被中间人嗅探凭据，必须立即切换到 SSH。\n\n';
    else if ((device.services || []).some(s => s.port === 445)) protoText = '检测到 **SMB(445)** 文件共享，存在永恒之蓝类 RCE 隐患，需限制来源 IP 并打补丁。\n\n';
    else if ((device.services || []).some(s => s.port === 3389)) protoText = '检测到 **RDP(3389)** 远程桌面，易被暴力破解，建议开启 NLA + 账户锁定策略。\n\n';
    else protoText = '未发现典型高危明文协议，仍需确认非标准端口运行的服务。\n\n';

    const latencyText = Number(device.latency) > 0 && Number(device.latency) < 3
      ? '极低延迟表示该设备通过有线或近距离 Wi-Fi 直接连接同一交换机/AP，属于本物理区域。\n\n'
      : '中等延迟提示可能经过 Wi-Fi 中继或下级交换机。\n\n';

    const riskLevel = highRisk > 0 ? '高危' : svcCount > 0 ? '中危' : '低危';
    const otherDeviceCount = Math.max(0, devices.length - 1);

    const fullText =
      '### 用户画像\n' +
      `根据设备特征（IP: **${device.ip}**，类别：${catLabel}，厂商：${device.type || '未识别'}），初步判断如下：\n\n` +
      '- **设备用途**：' + usageText +
      '- **使用场景**：位于网段 **' + scanContext.cidr + '**，与本机同一子网，延迟 ' + latency + '。' + latencyText +
      '- **使用者画像推测**：结合开放服务 ' + svcCount + ' 个，高危端口 ' + highRisk + ' 个。' + svcText +
      '### 安全风险\n\n' +
      `- **端口暴露风险**（${riskLevel}）：当前检测到 ${svcCount} 个开放服务，其中高危 ${highRisk} 个。` + portRiskText +
      '- **协议安全风险**（中危）：' + protoText +
      `- **横向移动风险**（中危）：与本机同网段且无端口隔离迹象，一旦被攻陷，可作为跳板横向探测 ${scanContext.cidr} 内的其它 ${otherDeviceCount} 台设备。\n\n` +
      '### 建议措施\n\n' +
      `1. **端口收敛**：关闭所有非业务必需的开放端口（当前 ${svcCount} 个），仅从白名单 IP 允许访问管理端口。\n` +
      `2. **协议升级**：将 Telnet/FTP 等明文协议替换为 SSH/SFTP/SMBv3，启用传输加密与强密码策略。\n` +
      `3. **补丁与固件**：更新 ${catLabel} 操作系统/固件至最新稳定版，重点修复 SMB、RDP、Web 服务相关 CVE。\n` +
      `4. **访问控制**：在网关或本地防火墙增加源 IP 限制，管理类端口（22/23/3389/5900）仅允许运维网段访问。\n` +
      `5. **持续监测**：对 ${device.ip} 开启连续监控，观察延迟异常和端口变化，出现异常立即告警。\n`;

    // 模拟流式：按字符 chunk 输出，耗时约 1.5s
    const chunkSize = Math.max(2, Math.floor(fullText.length / 30));
    for (let i = 0; i < fullText.length; i += chunkSize) {
      await new Promise(r => setTimeout(r, 50));
      const chunk = fullText.slice(i, i + chunkSize);
      if (onChunk) onChunk(chunk);
    }
    return { success: true, content: fullText };
  }

  // ════════════════════════════════════════════════════════
  // 设备元数据管理（备注 / 标签 / 收藏 / 分组）
  // ════════════════════════════════════════════════════════

  function getDeviceMetaKey(device) {
    return device.mac && device.mac !== '00:00:00:00:00:00'
      ? device.mac.toUpperCase()
      : device.ip;
  }

  function getDeviceMeta(device) {
    const key = getDeviceMetaKey(device);
    return deviceMeta.devices[key] || null;
  }

  async function loadDeviceMeta() {
    try {
      const r = await api.deviceMetaGetAll();
      if (r && r.devices) {
        deviceMeta = r;
      }
    } catch (err) {
      console.error('加载设备元数据失败:', err);
    }
  }

  function renderDeviceMeta(device) {
    const favBtn = document.getElementById('detail-fav-btn');
    const badgesEl = document.getElementById('detail-meta-badges');
    if (!favBtn || !badgesEl) return;

    const meta = getDeviceMeta(device);
    const isFav = meta && meta.favorite;

    // 更新收藏按钮样式
    if (isFav) {
      favBtn.style.background = 'var(--scanner-state-warning-bg)';
      favBtn.style.color = 'var(--scanner-state-warning)';
      favBtn.style.borderColor = 'var(--scanner-state-warning)';
    } else {
      favBtn.style.background = 'var(--scanner-card)';
      favBtn.style.color = 'var(--scanner-ink-2)';
      favBtn.style.borderColor = 'var(--scanner-border)';
    }

    // 渲染标签徽章
    const badges = [];
    if (meta) {
      if (meta.favorite) badges.push('<span style="font-size:10px; padding:2px 8px; border-radius:999px; background:var(--scanner-state-warning-bg); color:var(--scanner-state-warning); font-weight:600;">★ 收藏</span>');
      if (meta.group) badges.push(`<span style="font-size:10px; padding:2px 8px; border-radius:999px; background:var(--scanner-state-info-bg); color:var(--scanner-state-info); font-weight:600;">📁 ${meta.group}</span>`);
      if (meta.tags) {
        meta.tags.split(',').map(t => t.trim()).filter(Boolean).forEach(tag => {
          badges.push(`<span style="font-size:10px; padding:2px 8px; border-radius:999px; background:var(--scanner-muted); color:var(--scanner-ink-2); font-weight:500;">#${tag}</span>`);
        });
      }
      if (meta.note) badges.push(`<span style="font-size:10px; padding:2px 8px; border-radius:999px; background:var(--scanner-state-success-bg); color:var(--scanner-state-success); font-weight:500;">📝 ${meta.note}</span>`);
    }
    badgesEl.innerHTML = badges.join('');
  }

  async function toggleFavorite(device) {
    const meta = getDeviceMeta(device) || {};
    const newFav = !meta.favorite;
    try {
      const r = await api.deviceMetaSave(device, { favorite: newFav });
      if (r.success) {
        deviceMeta.devices[r.key] = r.meta;
        renderDeviceMeta(device);
        showToast(newFav ? '已收藏' : '已取消收藏');
        renderDevices();
      }
    } catch (err) {
      showToast('操作失败: ' + err.message);
    }
  }

  function openMetaEditor() {
    if (!currentDetailDevice) { showToast('请先选择设备'); return; }
    const overlay = document.getElementById('meta-overlay');
    const meta = getDeviceMeta(currentDetailDevice) || {};

    document.getElementById('meta-note').value = meta.note || '';
    document.getElementById('meta-tags').value = meta.tags || '';
    document.getElementById('meta-group').value = meta.group || '';

    // 填充分组 datalist
    const groupList = document.getElementById('meta-group-list');
    groupList.innerHTML = (deviceMeta.groups || []).map(g => `<option value="${g}">`).join('');

    overlay.style.display = 'flex';
  }

  function closeMetaEditor() {
    const overlay = document.getElementById('meta-overlay');
    if (overlay) overlay.style.display = 'none';
  }

  async function saveMetaFromEditor() {
    if (!currentDetailDevice) return;
    const note = document.getElementById('meta-note').value.trim();
    const tags = document.getElementById('meta-tags').value.trim();
    const group = document.getElementById('meta-group').value.trim();

    try {
      const r = await api.deviceMetaSave(currentDetailDevice, { note, tags, group });
      if (r.success) {
        deviceMeta.devices[r.key] = r.meta;
        // 如果有新分组，添加到分组列表
        if (group && !(deviceMeta.groups || []).includes(group)) {
          deviceMeta.groups = deviceMeta.groups || [];
          deviceMeta.groups.push(group);
        }
        renderDeviceMeta(currentDetailDevice);
        closeMetaEditor();
        showToast('设备信息已保存');
        renderDevices();
      }
    } catch (err) {
      showToast('保存失败: ' + err.message);
    }
  }

  async function deleteDeviceMetaFromEditor() {
    if (!currentDetailDevice) return;
    try {
      const r = await api.deviceMetaDelete(currentDetailDevice);
      if (r.success) {
        const key = getDeviceMetaKey(currentDetailDevice);
        delete deviceMeta.devices[key];
        renderDeviceMeta(currentDetailDevice);
        closeMetaEditor();
        showToast('元数据已清除');
        renderDevices();
      }
    } catch (err) {
      showToast('清除失败: ' + err.message);
    }
  }

  // ════════════════════════════════════════════════════════
  // 网络诊断工具
  // ════════════════════════════════════════════════════════

  function setDiagResult(html) {
    const el = document.getElementById('diag-result');
    if (el) el.innerHTML = html;
  }

  function setDiagLoading(msg) {
    setDiagResult(`<div class="port-empty"><div class="action-panel-hint" style="margin-bottom:6px;">${msg}</div></div>`);
  }

  // Traceroute 路由追踪
  async function runTraceroute(device) {
    if (!device) return;
    // 展开诊断面板
    const panelBody = document.querySelector('#diag-panel .action-panel-body');
    if (panelBody && panelBody.style.display === 'none') {
      document.querySelector('#diag-panel .action-panel-header')?.click();
    }
    setDiagLoading(`正在追踪到 ${device.ip} 的路由，请稍候（最多 15 跳）...`);
    try {
      const r = await api.traceroute(device.ip, 15, 1500);
      if (r.success && r.hops && r.hops.length > 0) {
        const hopsHtml = r.hops.map((h, i) => {
          const status = h.timeout ? 'timeout' : 'ok';
          const statusColor = h.timeout ? 'var(--scanner-ink-3)' : 'var(--scanner-state-success)';
          const statusText = h.timeout ? '* * *' : `${h.ip || '？'}${h.latency != null ? ` (${h.latency}ms)` : ''}`;
          return `
            <div style="display:flex; align-items:center; gap:10px; padding:6px 8px; border-bottom:1px solid var(--scanner-border);">
              <span style="font-size:11px; font-weight:700; color:var(--scanner-ink-2); min-width:24px;">${i + 1}</span>
              <span style="font-size:12px; font-family:monospace; color:${statusColor}; flex:1;">${statusText}</span>
              ${h.hostname ? `<span style="font-size:10px; color:var(--scanner-ink-3);">${h.hostname}</span>` : ''}
            </div>
          `;
        }).join('');
        setDiagResult(`
          <div style="margin-bottom:6px; font-size:12px; font-weight:600; color:var(--scanner-ink);">路由追踪结果（${r.hops.length} 跳）</div>
          <div class="port-list">${hopsHtml}</div>
          <div class="action-panel-hint" style="margin-top:6px;">总耗时约 ${r.elapsed || '-'}ms</div>
        `);
      } else {
        setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-warning);">路由追踪未返回结果${r.error ? '：' + r.error : ''}</div>`);
      }
    } catch (err) {
      setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">路由追踪异常: ${err.message}</div>`);
    }
  }

  // DNS 查询
  async function runDnsQuery() {
    const name = document.getElementById('diag-dns-name')?.value.trim();
    const server = document.getElementById('diag-dns-server')?.value.trim();
    if (!name) { showToast('请输入域名或 IP'); return; }
    if (!currentDetailDevice) return;

    setDiagLoading(`正在查询 ${name} ...`);
    try {
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(name);
      const r = isIp
        ? await api.reverseDns(name, server || null)
        : await api.resolveDns(name, server || null);
      if (r.success) {
        const results = r.addresses || r.hostnames || [];
        if (results.length > 0) {
          const itemsHtml = results.map(addr => `
            <div style="display:flex; align-items:center; gap:8px; padding:6px 8px; border-bottom:1px solid var(--scanner-border);">
              <i data-lucide="${isIp ? 'arrow-right' : 'globe'}" style="width:12px; height:12px; color:var(--scanner-state-info);"></i>
              <span style="font-size:12px; font-family:monospace; color:var(--scanner-ink);">${addr}</span>
            </div>
          `).join('');
          setDiagResult(`
            <div style="margin-bottom:6px; font-size:12px; font-weight:600; color:var(--scanner-ink);">${isIp ? '反向 DNS' : '正向 DNS'} 查询结果（${results.length} 条）</div>
            <div class="port-list">${itemsHtml}</div>
            ${server ? `<div class="action-panel-hint" style="margin-top:6px;">DNS 服务器: ${server}</div>` : ''}
          `);
        } else {
          setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-warning);">未找到解析记录</div>`);
        }
      } else {
        setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">查询失败: ${r.error || '未知错误'}</div>`);
      }
    } catch (err) {
      setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">查询异常: ${err.message}</div>`);
    }
  }

  // 网速测试
  async function runSpeedTest(device) {
    if (!device) return;
    const panelBody = document.querySelector('#diag-panel .action-panel-body');
    if (panelBody && panelBody.style.display === 'none') {
      document.querySelector('#diag-panel .action-panel-header')?.click();
    }
    setDiagLoading(`正在测试到 ${device.ip} 的链路质量...`);
    try {
      const r = await api.speedTest(device.ip, {});
      if (r.success) {
        const metrics = r.metrics || r;
        const tcpColor = metrics.tcpConnectTime != null ? 'var(--scanner-state-success)' : 'var(--scanner-ink-3)';
        const quality = metrics.quality || 'unknown';
        const qualityColor = quality === 'good' ? 'var(--scanner-state-success)' : quality === 'fair' ? 'var(--scanner-state-warning)' : 'var(--scanner-state-error)';
        const qualityLabel = quality === 'good' ? '优秀' : quality === 'fair' ? '一般' : quality === 'poor' ? '较差' : '未知';

        const rows = [
          { label: 'TCP 连接时间', value: metrics.tcpConnectTime != null ? `${metrics.tcpConnectTime} ms` : '不可达', color: tcpColor, port: metrics.tcpPort },
          { label: 'ICMP 延迟', value: metrics.icmpLatency != null ? `${metrics.icmpLatency} ms` : '-', color: 'var(--scanner-ink)' },
          { label: 'ICMP 丢包率', value: metrics.icmpLoss != null ? `${metrics.icmpLoss}%` : '-', color: metrics.icmpLoss > 0 ? 'var(--scanner-state-error)' : 'var(--scanner-ink)' },
          { label: '链路质量', value: qualityLabel, color: qualityColor },
          { label: '评估得分', value: metrics.score != null ? `${metrics.score}/100` : '-', color: 'var(--scanner-ink)' }
        ];
        const rowsHtml = rows.map(row => `
          <div style="display:flex; align-items:center; justify-content:space-between; padding:8px 10px; border-bottom:1px solid var(--scanner-border);">
            <span style="font-size:12px; color:var(--scanner-ink-2);">${row.label}</span>
            <span style="font-size:13px; font-weight:600; color:${row.color};">${row.value}${row.port ? ` <span style="font-size:10px; color:var(--scanner-ink-3);">(:${row.port})</span>` : ''}</span>
          </div>
        `).join('');
        setDiagResult(`
          <div style="margin-bottom:6px; font-size:12px; font-weight:600; color:var(--scanner-ink);">链路质量评估 — ${device.ip}</div>
          <div class="port-list">${rowsHtml}</div>
        `);
      } else {
        setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">测试失败: ${r.error || '未知错误'}</div>`);
      }
    } catch (err) {
      setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">测试异常: ${err.message}</div>`);
    }
  }

  // Wake-on-LAN 远程唤醒
  async function runWakeOnLan(device) {
    if (!device) return;
    if (!device.mac || device.mac === '00:00:00:00:00:00') {
      showToast('该设备无 MAC 地址，无法发送 WoL 魔术包');
      return;
    }
    const panelBody = document.querySelector('#diag-panel .action-panel-body');
    if (panelBody && panelBody.style.display === 'none') {
      document.querySelector('#diag-panel .action-panel-header')?.click();
    }
    setDiagLoading(`正在向 ${device.mac} 发送 Wake-on-LAN 魔术包...`);
    try {
      const broadcast = selectedAdapter ? selectedAdapter.broadcast : '255.255.255.255';
      const r = await api.wakeOnLan(device.mac, broadcast);
      if (r.success) {
        setDiagResult(`
          <div style="padding:12px; border-radius:8px; background:var(--scanner-state-success-bg); border:1px solid var(--scanner-state-success); text-align:center;">
            <i data-lucide="check-circle" style="width:24px; height:24px; color:var(--scanner-state-success); margin-bottom:6px;"></i>
            <div style="font-size:13px; font-weight:600; color:var(--scanner-state-success);">魔术包已发送</div>
            <div style="font-size:11px; color:var(--scanner-ink-2); margin-top:4px;">MAC: ${device.mac} | 广播: ${broadcast}</div>
            <div class="action-panel-hint" style="margin-top:8px;">设备需要支持 WoL 并已配置才能被唤醒</div>
          </div>
        `);
        lucide.createIcons();
      } else {
        setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">唤醒失败: ${r.error || '未知错误'}</div>`);
      }
    } catch (err) {
      setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">唤醒异常: ${err.message}</div>`);
    }
  }

  // 远程关机 / 重启
  async function runRemoteShutdown(device) {
    if (!device) return;
    const action = confirm(`确定要远程关闭/重启 ${device.ip} 吗？\n\n点击"确定"执行关机，"取消"放弃。\n注意：目标设备需已配置远程关机权限（如 shutdown 命令）。`);
    if (!action) return;

    const panelBody = document.querySelector('#diag-panel .action-panel-body');
    if (panelBody && panelBody.style.display === 'none') {
      document.querySelector('#diag-panel .action-panel-header')?.click();
    }
    setDiagLoading(`正在向 ${device.ip} 发送远程关机指令...`);
    try {
      const r = await api.remoteShutdown(device.ip, { action: 'shutdown', timeout: 10 });
      if (r.success) {
        setDiagResult(`
          <div style="padding:12px; border-radius:8px; background:var(--scanner-state-warning-bg); border:1px solid var(--scanner-state-warning); text-align:center;">
            <i data-lucide="alert-triangle" style="width:24px; height:24px; color:var(--scanner-state-warning); margin-bottom:6px;"></i>
            <div style="font-size:13px; font-weight:600; color:var(--scanner-state-warning);">关机指令已发送</div>
            <div style="font-size:11px; color:var(--scanner-ink-2); margin-top:4px;">目标: ${device.ip}</div>
          </div>
        `);
        lucide.createIcons();
      } else {
        setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">关机失败: ${r.error || '权限不足或目标不支持'}</div>`);
      }
    } catch (err) {
      setDiagResult(`<div class="port-empty" style="color:var(--scanner-state-error);">关机异常: ${err.message}</div>`);
    }
  }

  // OS 指纹检测
  async function runOsDetect(device) {
    if (!device) return;
    const resultEl = document.getElementById('portscan-result');
    if (!resultEl) return;
    const osBtn = document.getElementById('portscan-os-btn');
    if (osBtn) osBtn.disabled = true;
    resultEl.innerHTML = '<div class="port-empty"><div class="action-panel-hint" style="margin-bottom:6px;">正在进行 OS 指纹检测，请稍候...</div></div>';
    try {
      const r = await api.detectOs(device);
      if (r.success) {
        const os = r.os || {};
        const confidence = os.confidence != null ? `${Math.round(os.confidence * 100)}%` : '-';
        const rows = [
          { label: '操作系统', value: os.name || '未知' },
          { label: '版本', value: os.version || '-' },
          { label: '架构', value: os.arch || '-' },
          { label: '置信度', value: confidence },
          { label: '检测方法', value: os.method || '-' }
        ];
        const rowsHtml = rows.map(row => `
          <div style="display:flex; align-items:center; justify-content:space-between; padding:8px 10px; border-bottom:1px solid var(--scanner-border);">
            <span style="font-size:12px; color:var(--scanner-ink-2);">${row.label}</span>
            <span style="font-size:13px; font-weight:600; color:var(--scanner-ink);">${row.value}</span>
          </div>
        `).join('');
        resultEl.innerHTML = `
          <div style="margin-bottom:6px; font-size:12px; font-weight:600; color:var(--scanner-ink); display:flex; align-items:center; gap:6px;">
            <i data-lucide="cpu" style="width:14px; height:14px; color:var(--scanner-primary);"></i>
            OS 指纹检测结果
          </div>
          <div class="port-list">${rowsHtml}</div>
          ${os.details ? `<div class="action-panel-hint" style="margin-top:6px;">${os.details}</div>` : ''}
        `;
        lucide.createIcons();
      } else {
        resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-warning);">OS 检测失败: ${r.error || '无法确定操作系统'}</div>`;
      }
    } catch (err) {
      resultEl.innerHTML = `<div class="port-empty" style="color:var(--scanner-state-error);">OS 检测异常: ${err.message}</div>`;
    } finally {
      if (osBtn) osBtn.disabled = false;
    }
  }

  // ════════════════════════════════════════════════════════
  // 可视化统计图表（纯 SVG 实现，无外部依赖）
  // ════════════════════════════════════════════════════════

  function showVizPanel() {
    const panel = document.getElementById('viz-panel');
    panel.style.display = 'flex';
    renderVendorChart();
    renderPortChart();
    renderTrendChart();
    lucide.createIcons();
  }

  function hideVizPanel() {
    const panel = document.getElementById('viz-panel');
    if (panel) panel.style.display = 'none';
  }

  // 厂商分布饼图
  function renderVendorChart() {
    const el = document.getElementById('viz-vendor-chart');
    if (!el) return;
    const vendors = {};
    devices.forEach(d => {
      const v = d.type || '未知';
      vendors[v] = (vendors[v] || 0) + 1;
    });
    const entries = Object.entries(vendors).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, n]) => s + n, 0);
    if (!total) { el.innerHTML = '<div class="port-empty">暂无设备数据</div>'; return; }

    const colors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6', '#64748b'];
    const cx = 90, cy = 90, r = 70;
    let angle = -Math.PI / 2;
    const slices = entries.map(([name, count], i) => {
      const pct = count / total;
      const startAngle = angle;
      const endAngle = angle + pct * 2 * Math.PI;
      angle = endAngle;
      const x1 = cx + r * Math.cos(startAngle);
      const y1 = cy + r * Math.sin(startAngle);
      const x2 = cx + r * Math.cos(endAngle);
      const y2 = cy + r * Math.sin(endAngle);
      const largeArc = pct > 0.5 ? 1 : 0;
      const color = colors[i % colors.length];
      return { name, count, pct, color, path: `M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${largeArc} 1 ${x2},${y2} Z` };
    });

    const svgSlices = slices.map(s => `<path d="${s.path}" fill="${s.color}" stroke="var(--scanner-card)" stroke-width="2"/>`).join('');
    const legend = slices.map(s => `
      <div style="display:flex; align-items:center; gap:6px; font-size:11px;">
        <span style="width:10px; height:10px; border-radius:2px; background:${s.color};"></span>
        <span style="color:var(--scanner-ink); flex:1;">${s.name}</span>
        <span style="color:var(--scanner-ink-2); font-weight:600;">${s.count} (${Math.round(s.pct * 100)}%)</span>
      </div>
    `).join('');

    el.innerHTML = `
      <div style="display:flex; gap:16px; align-items:center;">
        <svg width="180" height="180" viewBox="0 0 180 180" style="flex-shrink:0;">
          ${svgSlices}
          <circle cx="${cx}" cy="${cy}" r="36" fill="var(--scanner-card)"/>
          <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="20" font-weight="700" fill="var(--scanner-ink)">${total}</text>
          <text x="${cx}" y="${cy + 14}" text-anchor="middle" font-size="10" fill="var(--scanner-ink-3)">设备</text>
        </svg>
        <div style="flex:1; display:flex; flex-direction:column; gap:4px;">${legend}</div>
      </div>
    `;
  }

  // 开放端口 Top 10 柱状图
  function renderPortChart() {
    const el = document.getElementById('viz-port-chart');
    if (!el) return;
    const portCounts = {};
    devices.forEach(d => {
      (d.services || []).forEach(s => {
        const port = typeof s === 'object' ? s.port : s;
        portCounts[port] = (portCounts[port] || 0) + 1;
      });
    });
    const entries = Object.entries(portCounts).map(([p, c]) => ({ port: parseInt(p), count: c })).sort((a, b) => b.count - a.count).slice(0, 10);
    if (!entries.length) { el.innerHTML = '<div class="port-empty">暂无端口扫描数据</div>'; return; }

    const maxCount = entries[0].count;
    const barHeight = 22;
    const barGap = 6;
    const labelWidth = 70;
    const chartWidth = 200;

    const bars = entries.map((e, i) => {
      const w = (e.count / maxCount) * chartWidth;
      const y = i * (barHeight + barGap);
      const svcName = PORT_SERVICES[e.port] || '';
      return `
        <g>
          <text x="${labelWidth - 6}" y="${y + barHeight / 2 + 4}" text-anchor="end" font-size="11" fill="var(--scanner-ink-2)" font-family="monospace">${e.port}</text>
          <rect x="${labelWidth}" y="${y}" width="${chartWidth}" height="${barHeight}" rx="3" fill="var(--scanner-muted)"/>
          <rect x="${labelWidth}" y="${y}" width="${w}" height="${barHeight}" rx="3" fill="var(--scanner-primary)"/>
          <text x="${labelWidth + w + 6}" y="${y + barHeight / 2 + 4}" font-size="11" fill="var(--scanner-ink)" font-weight="600">${e.count}</text>
          ${svcName ? `<text x="${labelWidth + chartWidth + 30}" y="${y + barHeight / 2 + 4}" font-size="10" fill="var(--scanner-ink-3)">${svcName}</text>` : ''}
        </g>
      `;
    }).join('');

    const totalHeight = entries.length * (barHeight + barGap);
    el.innerHTML = `
      <svg width="100%" height="${totalHeight}" viewBox="0 0 ${labelWidth + chartWidth + 100} ${totalHeight}" style="overflow:visible;">
        ${bars}
      </svg>
    `;
  }

  // 扫描历史趋势图
  async function renderTrendChart() {
    const el = document.getElementById('viz-trend-chart');
    if (!el) return;

    // 从持久化历史数据库加载
    let records = [];
    try {
      const r = await api.historyDbGet(20);
      records = r.records || [];
    } catch {
      // 回退到 localStorage
    }

    if (!records.length) { el.innerHTML = '<div class="port-empty">暂无扫描历史数据，完成一次扫描后将自动记录</div>'; return; }

    records.reverse(); // 按时间正序
    const width = 580;
    const height = 160;
    const padding = { top: 20, right: 20, bottom: 30, left: 40 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    const maxOnline = Math.max(...records.map(r => r.onlineCount || 0), 1);
    const minOnline = 0;
    const xStep = records.length > 1 ? chartW / (records.length - 1) : 0;

    const points = records.map((r, i) => ({
      x: padding.left + i * xStep,
      y: padding.top + chartH - ((r.onlineCount || 0) / maxOnline) * chartH,
      val: r.onlineCount || 0,
      time: r.timestamp ? new Date(r.timestamp).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-'
    }));

    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ');
    const areaPath = linePath + ` L${points[points.length - 1].x},${padding.top + chartH} L${points[0].x},${padding.top + chartH} Z`;
    const dots = points.map(p => `<circle cx="${p.x}" cy="${p.y}" r="3" fill="var(--scanner-primary)" stroke="var(--scanner-card)" stroke-width="1.5"><title>${p.time}: ${p.val} 台在线</title></circle>`).join('');
    const labels = points.map((p, i) => {
      if (records.length > 8 && i % Math.ceil(records.length / 6) !== 0) return '';
      return `<text x="${p.x}" y="${height - 8}" text-anchor="middle" font-size="9" fill="var(--scanner-ink-3)">${p.time.split(' ')[0] || ''}</text>`;
    }).join('');
    const yLabels = [0, Math.round(maxOnline / 2), maxOnline].map((v, i) => {
      const y = padding.top + chartH - (v / maxOnline) * chartH;
      return `<text x="${padding.left - 6}" y="${y + 4}" text-anchor="end" font-size="9" fill="var(--scanner-ink-3)">${v}</text>`;
    }).join('');

    el.innerHTML = `
      <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow:visible;">
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--scanner-primary)" stop-opacity="0.3"/>
            <stop offset="100%" stop-color="var(--scanner-primary)" stop-opacity="0"/>
          </linearGradient>
        </defs>
        <line x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${padding.top + chartH}" stroke="var(--scanner-border)" stroke-width="1"/>
        <line x1="${padding.left}" y1="${padding.top + chartH}" x2="${padding.left + chartW}" y2="${padding.top + chartH}" stroke="var(--scanner-border)" stroke-width="1"/>
        ${yLabels}
        <path d="${areaPath}" fill="url(#trendGrad)"/>
        <path d="${linePath}" fill="none" stroke="var(--scanner-primary)" stroke-width="2"/>
        ${dots}
        ${labels}
      </svg>
      <div class="action-panel-hint" style="margin-top:4px;">最近 ${records.length} 次扫描的在线设备数量趋势</div>
    `;
  }

  // ════════════════════════════════════════════════════════
  // 扫描历史持久化
  // ════════════════════════════════════════════════════════

  async function saveHistoryToDb(record) {
    try {
      await api.historyDbSave(record);
    } catch (err) {
      console.error('保存历史记录失败:', err);
    }
  }

  async function init() {
    try {
      localInfo = await api.getLocalInfo();
      selectedAdapter = localInfo.activeAdapter || localInfo.adapters[0] || null;
      renderLocalInfo();
      updateScanTarget();
      updateModeButtons();
      updateFilterButtons();
      // 加载设备元数据（备注 / 标签 / 收藏 / 分组）
      await loadDeviceMeta();
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
