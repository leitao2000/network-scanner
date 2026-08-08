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

  const modeConfig = {
    quick: { label: '快速', concurrency: 80, timeout: 800 },
    standard: { label: '标准', concurrency: 50, timeout: 1200 },
    deep: { label: '深度', concurrency: 25, timeout: 3000 },
    ai: { label: 'AI', concurrency: 50, timeout: 1500 }
  };

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

    // 层级布局数据
    const localDevice = allDevices.find(d => d.type === '本机') || {
      ip: selectedAdapter?.address || '127.0.0.1',
      type: '本机',
      hostname: localInfo?.hostname || '本机',
      status: '在线',
      mac: localInfo?.mac || '',
      latency: 0,
      services: []
    };

    const gateway = allDevices.find(d => d.type?.includes('路由') || d.type?.includes('网关'));
    const otherDevices = allDevices.filter(d =>
      d !== localDevice && d !== gateway && d.type !== '本机'
    );

    // 定义层级
    const layers = [];

    // Layer 0: Internet（虚拟节点）
    const hasGateway = !!gateway;
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

    // Layer 1: 网关（如果有）或 本机
    if (hasGateway) {
      layers.push([gateway]);
    } else {
      layers.push([localDevice]);
    }

    // Layer 2: 本机（如果有网关）
    if (hasGateway) {
      layers.push([localDevice]);
    }

    // Layer 3+: 其他设备（每行最多 5 个）
    if (otherDevices.length > 0) {
      const chunkSize = 5;
      for (let i = 0; i < otherDevices.length; i += chunkSize) {
        layers.push(otherDevices.slice(i, i + chunkSize));
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

    // 渲染连线
    renderEdges(edgesEl, nodePositions, layers, canvasWidth, canvasHeight);

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

  // 渲染连线
  function renderEdges(svg, positions, layers, canvasWidth, canvasHeight) {
    if (!svg) return;
    svg.setAttribute('width', canvasWidth);
    svg.setAttribute('height', canvasHeight);
    svg.setAttribute('viewBox', `0 0 ${canvasWidth} ${canvasHeight}`);

    const parts = [];

    // 连线规则：Internet -> 网关 -> 本机 -> 其他设备
    for (let i = 0; i < layers.length - 1; i++) {
      const currentLayer = layers[i];
      const nextLayer = layers[i + 1];

      for (const srcDevice of currentLayer) {
        const srcKey = srcDevice.isInternet ? 'internet' : (srcDevice.ip || '');
        const srcPos = positions[srcKey];
        if (!srcPos) continue;

        for (const dstDevice of nextLayer) {
          const dstKey = dstDevice.ip || '';
          const dstPos = positions[dstKey];
          if (!dstPos) continue;

          // 从源卡片底部中心到目标卡片顶部中心
          const x1 = srcPos.x;
          const y1 = srcPos.top + 90; // nodeHeight
          const x2 = dstPos.x;
          const y2 = dstPos.top;

          // 从 Internet 到网关用虚线，其他用实线
          const isDashed = srcDevice.isInternet;
          const color = isDashed ? 'var(--scanner-ink-3)' : 'var(--scanner-primary)';

          // 贝塞尔曲线
          const midY = (y1 + y2) / 2;
          const d = `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`;

          parts.push(`<path d="${d}" fill="none" stroke="${color}" stroke-width="1.5" stroke-dasharray="${isDashed ? '5 4' : '0'}" opacity="${isDashed ? 0.5 : 0.4}"/>`);
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
    const result = await api.exportResult({
      cidr: selectedAdapter?.cidr || '',
      devices,
      elapsed: Date.now() - scanStartTime
    });
    if (result.success) {
      // exported
    } else if (!result.canceled) {
      alert(`导出失败: ${result.error}`);
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
      { label: '延迟', value: device.latency != null ? `${device.latency} ms` : '-', mono: true },
      { label: '服务端口', value: device.services && device.services.length ? device.services.join(', ') : '无' }
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

  function hideDeviceDetail() {
    const overlay = document.getElementById('device-detail-overlay');
    const drawer = document.getElementById('device-detail-drawer');
    drawer.style.transform = 'translateX(100%)';
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 260);
  }

  function bindEvents() {
    els.btnStart.addEventListener('click', startScan);
    els.btnStop.addEventListener('click', stopScan);
    els.btnExport.addEventListener('click', exportResult);

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

    // 拓扑图节点点击 -> 显示详情
    document.getElementById('topology-nodes').addEventListener('click', (e) => {
      const card = e.target.closest('.topo-node-card');
      if (!card) return;
      const ip = card.dataset.topoIp;
      const device = devices.find(d => d.ip === ip);
      if (device) showDeviceDetail(device);
    });

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
