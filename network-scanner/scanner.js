const os = require('os');
const { spawn } = require('child_process');
const { promisify } = require('util');
const net = require('net');
const dns = require('dns');
const https = require('https');
const { EventEmitter } = require('events');

const dnsReverse = promisify(dns.reverse);

/**
 * 本地网络扫描器
 * 使用 Node.js 内置模块 + 系统命令实现，无需外部 npm 依赖。
 * 注意：Windows 下 ICMP / ARP 扫描通常需要管理员权限才能获得完整结果。
 */
class Scanner extends EventEmitter {
  constructor() {
    super();
    this.isScanning = false;
    this.shouldStop = false;
    this.activeProcesses = new Set();
  }

  /**
   * 校验 IPv4 地址
   */
  static isValidIPv4(ip) {
    if (typeof ip !== 'string') return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
      const num = parseInt(part, 10);
      return /^\d+$/.test(part) && num >= 0 && num <= 255 && String(num) === part;
    });
  }

  /**
   * 校验 CIDR
   */
  static isValidCIDR(cidr) {
    if (typeof cidr !== 'string') return false;
    const [ip, prefix] = cidr.split('/');
    if (!Scanner.isValidIPv4(ip)) return false;
    if (!/^\d+$/.test(prefix)) return false;
    const p = parseInt(prefix, 10);
    return p >= 0 && p <= 32;
  }

  /**
   * 获取本机网络信息
   */
  static async getLocalInfo() {
    const interfaces = os.networkInterfaces();
    const adapters = [];
    let activeAdapter = null;

    const gateways = await Scanner.getDefaultGateways();

    for (const [name, addrs] of Object.entries(interfaces)) {
      for (const addr of addrs) {
        if (addr.family === 'IPv4' && !addr.internal) {
          const prefix = Scanner.maskToPrefix(addr.netmask);
          const network = Scanner.getNetworkAddress(addr.address, addr.netmask);
          const broadcast = Scanner.getBroadcastAddress(addr.address, addr.netmask);
          const cidr = `${network}/${prefix}`;
          const gateway = gateways.find(g => Scanner.isSameSubnet(g, network, prefix));
          const adapter = {
            name,
            address: addr.address,
            netmask: addr.netmask,
            cidr,
            network,
            broadcast,
            gateway: gateway || null,
            mac: addr.mac || '00:00:00:00:00:00',
            isActive: false
          };

          // 选择优先级：有真实默认网关 > 非虚拟 > 第一个
          const isVirtual = /vmware|virtualbox|vbox|hyper-v|docker/i.test(name);
          const hasGateway = !!gateway;
          if (!activeAdapter ||
              (hasGateway && !activeAdapter.hasGateway) ||
              (hasGateway === activeAdapter.hasGateway && !isVirtual && activeAdapter.isVirtual)) {
            activeAdapter = { adapter, isVirtual, hasGateway };
          }

          adapters.push(adapter);
        }
      }
    }

    if (activeAdapter) {
      activeAdapter.adapter.isActive = true;
    }

    return {
      hostname: os.hostname(),
      platform: `${os.type()} ${os.release()}`,
      uptime: Scanner.formatUptime(os.uptime()),
      user: process.env.USERNAME || process.env.USER || 'unknown',
      adapters,
      activeAdapter: activeAdapter ? activeAdapter.adapter : null
    };
  }

  /**
   * 判断 IP 是否在指定子网内
   */
  static isSameSubnet(ip, network, prefix) {
    if (!Scanner.isValidIPv4(ip) || !Scanner.isValidIPv4(network)) return false;
    const ipInt = Scanner.ipToInt(ip);
    const netInt = Scanner.ipToInt(network);
    const mask = 0xffffffff << (32 - prefix);
    return (ipInt & mask) === (netInt & mask);
  }

  /**
   * 获取默认网关列表
   */
  static async getDefaultGateways() {
    const gateways = [];
    try {
      if (process.platform === 'win32') {
        const output = await Scanner.spawnOutput('route', ['print', '0.0.0.0']);
        for (const line of output.split('\n')) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 3 && parts[0] === '0.0.0.0' && parts[1] === '0.0.0.0') {
            if (Scanner.isValidIPv4(parts[2])) gateways.push(parts[2]);
          }
        }
      } else {
        const output = await Scanner.spawnOutput('ip', ['route', 'show', 'default']);
        for (const line of output.split('\n')) {
          const match = line.match(/via\s+(\d+\.\d+\.\d+\.\d+)/);
          if (match && Scanner.isValidIPv4(match[1])) gateways.push(match[1]);
        }
      }
    } catch {
      // ignore
    }
    return gateways;
  }

  /**
   * 将子网掩码转为前缀长度
   */
  static maskToPrefix(netmask) {
    return netmask
      .split('.')
      .map(Number)
      .reduce((acc, part) => acc + ((part >>> 0).toString(2).match(/1/g) || []).length, 0);
  }

  /**
   * 计算网络地址
   */
  static getNetworkAddress(ip, mask) {
    const ipParts = ip.split('.').map(Number);
    const maskParts = mask.split('.').map(Number);
    return ipParts.map((part, i) => part & maskParts[i]).join('.');
  }

  /**
   * 计算广播地址
   */
  static getBroadcastAddress(ip, mask) {
    const ipParts = ip.split('.').map(Number);
    const maskParts = mask.split('.').map(Number);
    return ipParts.map((part, i) => part | (255 - maskParts[i])).join('.');
  }

  /**
   * 格式化运行时长
   */
  static formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  }

  /**
   * 解析 CIDR 为 IP 列表
   */
  static parseCidr(cidr, maxHosts = 4094) {
    if (!Scanner.isValidCIDR(cidr)) {
      throw new Error(`无效的 CIDR: ${cidr}`);
    }

    const [ip, prefix] = cidr.split('/');
    const prefixLen = parseInt(prefix, 10);

    if (prefixLen < 20) {
      throw new Error(`子网过大，最大支持 /20（${maxHosts} 主机），当前 /${prefixLen}`);
    }

    const ipInt = Scanner.ipToInt(ip);
    const networkInt = ipInt & (0xffffffff << (32 - prefixLen));

    if (prefixLen === 32) {
      return [ip];
    }

    if (prefixLen === 31) {
      return [Scanner.intToIp(networkInt), Scanner.intToIp(networkInt + 1)];
    }

    const hostCount = Math.pow(2, 32 - prefixLen) - 2;
    if (hostCount > maxHosts) {
      throw new Error(`主机数 ${hostCount} 超过限制 ${maxHosts}`);
    }

    const ips = [];
    for (let i = 1; i <= hostCount; i++) {
      ips.push(Scanner.intToIp(networkInt + i));
    }
    return ips;
  }

  static ipToInt(ip) {
    return ip.split('.').reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0;
  }

  static intToIp(int) {
    return [(int >>> 24) & 0xff, (int >>> 16) & 0xff, (int >>> 8) & 0xff, int & 0xff].join('.');
  }

  /**
   * 执行一次 ping 探测（使用 spawn 避免命令注入）
   */
  async pingOnce(host, timeout = 2000) {
    if (!Scanner.isValidIPv4(host)) {
      return { alive: false, latency: null, error: 'invalid host' };
    }

    const args = process.platform === 'win32'
      ? ['-n', '1', '-w', timeout.toString(), host]
      : ['-c', '1', '-W', Math.ceil(timeout / 1000).toString(), host];

    const start = Date.now();
    let stdout = '';
    let killed = false;

    return new Promise((resolve) => {
      const proc = spawn('ping', args, { shell: false });
      this.activeProcesses.add(proc);

      const timer = setTimeout(() => {
        killed = true;
        this.killProcess(proc);
        resolve({ alive: false, latency: null });
      }, timeout + 500);

      proc.stdout.on('data', (data) => { stdout += data.toString(); });
      proc.stderr.on('data', (data) => { stdout += data.toString(); });

      proc.on('error', () => {
        clearTimeout(timer);
        this.activeProcesses.delete(proc);
        if (!killed) resolve({ alive: false, latency: null });
      });

      proc.on('close', (code) => {
        clearTimeout(timer);
        this.activeProcesses.delete(proc);
        if (killed) return;

        const elapsed = Date.now() - start;

        // 通过输出内容判断是否真正收到回包（比 exit code 更可靠）
        // Windows 下 ping 即使目标不可达也可能返回 code 0，但回包必定包含 TTL=
        const hasReply = /TTL=/i.test(stdout) || /ttl=/i.test(stdout);
        if (!hasReply) {
          resolve({ alive: false, latency: null });
          return;
        }

        let latency = elapsed;
        if (process.platform === 'win32') {
          const match = stdout.match(/时间[<=](\d+)ms|time[<=](\d+)ms|时间=(\d+)ms|time=(\d+)ms/i);
          latency = match ? parseInt(match[1] || match[2] || match[3] || match[4], 10) : elapsed;
        } else {
          const match = stdout.match(/time[<=]([\d.]+)\s*ms/i);
          latency = match ? parseFloat(match[1]) : elapsed;
        }

        resolve({ alive: true, latency });
      });
    });
  }

  /**
   * 执行 ping 探测（支持重试）
   */
  async ping(host, timeout = 2000, retries = 1) {
    for (let i = 0; i < retries; i++) {
      if (this.shouldStop) return { alive: false, latency: null };
      const result = await this.pingOnce(host, timeout);
      if (result.alive) return result;
    }
    return { alive: false, latency: null };
  }

  /**
   * ICMP 探测 + TCP 兜底
   */
  async probeHost(ip, options = {}) {
    const timeout = options.timeout || 2000;
    const retries = options.retries || 1;
    // 只探测最常见端口，减少等待时间
    const tcpPorts = options.tcpPorts || [445, 80, 22];

    // 1. ICMP
    const pingResult = await this.ping(ip, timeout, retries);
    if (pingResult.alive) {
      return { alive: true, latency: pingResult.latency, method: 'icmp' };
    }

    if (this.shouldStop) return { alive: false, latency: null };

    // 2. TCP 兜底（并行探测，超时缩短到 800ms）
    const tcpStart = Date.now();
    const portResults = await Promise.all(
      tcpPorts.map(port => this.checkPort(ip, port, Math.min(timeout, 800)))
    );
    if (this.shouldStop) return { alive: false, latency: null };
    if (portResults.some(isOpen => isOpen)) {
      return { alive: true, latency: Date.now() - tcpStart, method: 'tcp' };
    }

    return { alive: false, latency: null };
  }

  /**
   * 安全执行系统命令并返回 stdout
   */
  static spawnOutput(command, args, timeout = 10000) {
    return new Promise((resolve, reject) => {
      const proc = spawn(command, args, { shell: false });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        proc.kill();
        reject(new Error('spawn timeout'));
      }, timeout);

      proc.stdout.on('data', (data) => { stdout += data.toString(); });
      proc.stderr.on('data', (data) => { stderr += data.toString(); });
      proc.on('error', reject);
      proc.on('close', (code) => {
        clearTimeout(timer);
        if (code !== 0 && !stdout) {
          reject(new Error(stderr || `command failed with ${code}`));
        } else {
          resolve(stdout);
        }
      });
    });
  }

  /**
   * 获取 ARP 表
   */
  static async getArpTable() {
    const command = process.platform === 'win32' ? 'arp' : 'arp';
    const args = process.platform === 'win32' ? ['-a'] : ['-an'];
    try {
      const stdout = await Scanner.spawnOutput(command, args, 10000);
      return Scanner.parseArpTable(stdout);
    } catch (error) {
      return { entries: [], error: error.message };
    }
  }

  static parseArpTable(output) {
    const entries = [];
    const lines = output.split('\n');

    for (const line of lines) {
      let match;
      if (process.platform === 'win32') {
        // Windows ARP 表格式：IP  MAC(用-分隔)  类型(动态/静态)
        match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17}|incomplete)\s+(\S+)/);
      } else {
        match = line.match(/\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:-]{17}|incomplete)\s+\[([a-z]+)\]/);
      }

      if (match) {
        const ip = match[1];
        const mac = match[2].toUpperCase().replace(/-/g, ':');
        const type = match[3];
        entries.push({ ip, mac, type });
      }
    }

    return { entries };
  }

  /**
   * 通过 MAC 地址推断设备类型（静态兼容方法，内部调用新版 inferDeviceType）
   */
  static inferDeviceTypeLegacy(mac) {
    if (!mac || mac === '00:00:00:00:00:00') return '未知';
    const result = Scanner.inferDeviceType(mac);
    return result.type;
  }

  /**
   * 解析主机名（DNS → NetBIOS → nslookup）
   */
  static async resolveHostname(ip, timeout = 1000) {
    if (!Scanner.isValidIPv4(ip)) return null;

    const withTimeout = (promise, ms) => Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
    ]);

    // 1. DNS 反查（最快，500ms 超时）
    try {
      const hostnames = await withTimeout(dnsReverse(ip), 500);
      if (hostnames && hostnames.length > 0) return hostnames[0];
    } catch {
      // fallthrough
    }

    // 2. NetBIOS 查询（本地网络最有效，1200ms 超时）
    try {
      const stdout = await Scanner.spawnOutput('nbtstat', ['-A', ip], 1200);
      // 解析 NetBIOS Remote Machine Name Table
      const nameMatch = stdout.match(/<00>\s+UNIQUE\s+(\S+)/i);
      if (nameMatch) return nameMatch[1];
      // 回退到 Host Name 行
      const hostMatch = stdout.match(/Host Name[\s:]+(\S+)/i);
      if (hostMatch) return hostMatch[1];
    } catch {
      // fallthrough
    }

    // 3. nslookup（最后手段）
    try {
      const stdout = await Scanner.spawnOutput('nslookup', [ip], 800);
      const match = stdout.match(/名称[:\s]+([^\r\n]+)/i) || stdout.match(/Name[:\s]+([^\r\n]+)/i);
      return match ? match[1].trim() : null;
    } catch {
      return null;
    }
  }

  /**
   * 扫描网段
   */
  async scanNetwork(options = {}) {
    if (this.isScanning) {
      throw new Error('已有扫描任务进行中');
    }

    this.isScanning = true;
    this.shouldStop = false;
    this.activeProcesses.clear();

    const localInfo = await Scanner.getLocalInfo();
    const activeAdapter = localInfo.activeAdapter || options.adapter;
    const cidr = options.cidr || (activeAdapter ? activeAdapter.cidr : null);

    if (!cidr) {
      this.isScanning = false;
      throw new Error('无法确定扫描目标网段');
    }

    let ips;
    try {
      ips = Scanner.parseCidr(cidr, options.maxHosts || 4094);
    } catch (error) {
      this.isScanning = false;
      throw error;
    }

    const concurrency = options.concurrency || 50;
    const timeout = options.timeout || 1500;
    const retries = options.retries || 1;
    const startTime = Date.now();
    const localIps = new Set(localInfo.adapters.map(a => a.address));

    // 预加载 ARP 表（仅用于 MAC 地址查询，不做存活判定）
    let arpResult = await Scanner.getArpTable();
    let arpMap = new Map(arpResult.entries.map(e => [e.ip, e.mac]));
    let lastArpRefresh = Date.now();

    const devices = [];
    const progressStep = Math.max(1, Math.floor(ips.length / 20));

    this.emit('progress', {
      phase: 'started',
      total: ips.length,
      scanned: 0,
      found: 0,
      elapsed: 0
    });

    for (let i = 0; i < ips.length; i += concurrency) {
      if (this.shouldStop) break;

      const batch = ips.slice(i, i + concurrency);
      const results = await Promise.all(
        batch.map(async (ip) => {
          const probe = await this.probeHost(ip, { timeout, retries });
          return { ip, ...probe };
        })
      );

      // 并行处理所有在线设备的 hostname 解析和 OUI 查询
      const aliveResults = results.filter(r => r.alive);
      const enrichedResults = await Promise.all(
        aliveResults.map(async (result) => {
          // 刷新 ARP 缓存（如果需要）
          let mac = arpMap.get(result.ip) || null;
          if (!mac && Date.now() - lastArpRefresh > 3000) {
            arpResult = await Scanner.getArpTable();
            arpMap = new Map(arpResult.entries.map(e => [e.ip, e.mac]));
            lastArpRefresh = Date.now();
            mac = arpMap.get(result.ip) || null;
          }

          // 并行执行 hostname 解析和 OUI 查询
          const [hostname, inferred] = await Promise.all([
            Scanner.resolveHostname(result.ip).catch(() => null),
            mac ? (async () => {
              const info = Scanner.inferDeviceType(mac, result.ip, activeAdapter?.gateway);
              if (info.category === 'unknown' && !Scanner.isPrivacyMac(mac)) {
                const online = await Scanner.lookupOuiOnline(mac);
                if (online.vendor) {
                  // 根据在线厂商名推断设备类型
                  const v = online.vendor.toLowerCase();
                  let cat = 'unknown';
                  if (/apple|samsung|huawei|xiaomi|oppo|vivo|google|oneplus|realme|motorola|nokia|honor|zte/.test(v)) cat = 'phone';
                  else if (/dell|hp|hewlett|lenovo|asus|acer|intel|realtek|microsoft|surface/.test(v)) cat = 'computer';
                  else if (/tp-link|d-link|netgear|cisco|asus|tenda|mercury|huawei|xiaomi/.test(v)) cat = 'router';
                  else if (/hikvision|dahua|axis/.test(v)) cat = 'camera';
                  else if (/vmware|virtualbox|microsoft|parallels|qemu/.test(v)) cat = 'virtual';

                  if (cat !== 'unknown') {
                    const label = Scanner.CATEGORY_LABELS[cat];
                    info.type = `${online.vendor} ${label}`;
                    info.category = cat;
                  } else {
                    info.type = `${online.vendor} 设备`;
                  }
                }
              }
              return info;
            })() : Promise.resolve({ type: '在线设备', category: 'unknown' })
          ]);

          let type = inferred.type;
          if (localIps.has(result.ip)) {
            type = '本机';
          }

          return {
            ip: result.ip,
            mac,
            hostname,
            type,
            category: inferred.category,
            status: '在线',
            latency: result.latency,
            method: result.method || 'icmp',
            services: []
          };
        })
      );

      for (const device of enrichedResults) {
        devices.push(device);
        this.emit('device', device);
      }

      if ((i + batch.length) % progressStep < concurrency || i + batch.length >= ips.length) {
        this.emit('progress', {
          phase: 'scanning',
          total: ips.length,
          scanned: Math.min(i + batch.length, ips.length),
          found: devices.length,
          elapsed: Date.now() - startTime
        });
      }
    }

    // 最终刷新 ARP，补充扫描过程中解析出的 MAC
    arpResult = await Scanner.getArpTable();
    arpMap = new Map(arpResult.entries.map(e => [e.ip, e.mac]));
    for (const device of devices) {
      if (!device.mac && arpMap.has(device.ip)) {
        device.mac = arpMap.get(device.ip);
        const inferred = Scanner.inferDeviceType(device.mac, device.ip, activeAdapter?.gateway);
        device.type = inferred.type;
        device.category = inferred.category;

        // 本地 OUI 查不到时，在线查询
        if (device.category === 'unknown' && !Scanner.isPrivacyMac(device.mac)) {
          const online = await Scanner.lookupOuiOnline(device.mac);
          if (online.vendor) {
            const v = online.vendor.toLowerCase();
            let cat = 'unknown';
            if (/apple|samsung|huawei|xiaomi|oppo|vivo|google|oneplus|realme|motorola|nokia|honor|zte/.test(v)) cat = 'phone';
            else if (/dell|hp|hewlett|lenovo|asus|acer|intel|realtek|microsoft|surface/.test(v)) cat = 'computer';
            else if (/tp-link|d-link|netgear|cisco|asus|tenda|mercury|huawei|xiaomi/.test(v)) cat = 'router';
            else if (/hikvision|dahua|axis/.test(v)) cat = 'camera';
            else if (/vmware|virtualbox|microsoft|parallels|qemu/.test(v)) cat = 'virtual';

            if (cat !== 'unknown') {
              device.type = `${online.vendor} ${Scanner.CATEGORY_LABELS[cat]}`;
              device.category = cat;
            } else {
              device.type = `${online.vendor} 设备`;
            }
          }
        }

        if (localIps.has(device.ip)) device.type = '本机';
        this.emit('deviceUpdate', device);
      }
    }

    // 对在线设备并行扫描常用端口
    if (!this.shouldStop && devices.length > 0) {
      this.emit('progress', {
        phase: 'portscanning',
        total: ips.length,
        scanned: ips.length,
        found: devices.length,
        elapsed: Date.now() - startTime
      });

      const portScanPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1900, 3306, 3389, 5353, 8080, 8443, 9100];
      const portScanResults = await Promise.all(
        devices.map(device => this.scanPorts(device.ip, portScanPorts))
      );
      for (let i = 0; i < devices.length; i++) {
        devices[i].services = portScanResults[i];
        this.emit('deviceUpdate', devices[i]);
      }
    }

    const elapsed = Date.now() - startTime;

    this.emit('progress', {
      phase: 'completed',
      total: ips.length,
      scanned: this.shouldStop ? Math.min(ips.length, ips.length) : ips.length,
      found: devices.length,
      elapsed
    });

    this.isScanning = false;
    this.killAllProcesses();

    return {
      cidr,
      totalHosts: ips.length,
      devices,
      elapsed
    };
  }

  /**
   * TCP 端口扫描
   */
  async scanPorts(host, ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080]) {
    if (!Scanner.isValidIPv4(host)) return [];
    const openPorts = [];

    // 并行扫描所有端口
    const results = await Promise.all(
      ports.map(port => this.checkPort(host, port, 800))
    );

    for (let i = 0; i < ports.length; i++) {
      if (results[i]) {
        const port = ports[i];
        const info = Scanner.PORT_INFO[port] || {};
        openPorts.push({
          port,
          name: info.name || '未知服务',
          desc: info.desc || '',
          risk: info.risk || 'low'
        });
      }
    }

    return openPorts;
  }

  checkPort(host, port, timeout = 1000) {
    return new Promise((resolve) => {
      if (!Scanner.isValidIPv4(host) || !Number.isInteger(port)) {
        resolve(false);
        return;
      }
      const socket = new net.Socket();
      let resolved = false;

      const cleanup = () => {
        if (!resolved) {
          resolved = true;
          socket.destroy();
        }
      };

      socket.setTimeout(timeout);
      socket.once('connect', () => {
        cleanup();
        resolve(true);
      });
      socket.once('error', () => {
        cleanup();
        resolve(false);
      });
      socket.once('timeout', () => {
        cleanup();
        resolve(false);
      });

      socket.connect(port, host);
    });
  }

  killProcess(proc) {
    try {
      if (proc && !proc.killed) {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', proc.pid.toString(), '/f', '/t'], { shell: false, detached: true });
        } else {
          proc.kill('SIGKILL');
        }
      }
    } catch {
      // ignore
    }
    this.activeProcesses.delete(proc);
  }

  killAllProcesses() {
    for (const proc of this.activeProcesses) {
      this.killProcess(proc);
    }
    this.activeProcesses.clear();
  }

  stop() {
    this.shouldStop = true;
    this.killAllProcesses();
  }
}

/**
 * OUI 前缀 → { vendor, category }
 * category: phone / computer / router / iot / camera / virtual / unknown
 */

/**
 * 常用端口说明表
 * risk: low / medium / high
 */
Scanner.PORT_INFO = {
  21:   { name: 'FTP',         desc: '文件传输协议，用于上传/下载文件', risk: 'high' },
  22:   { name: 'SSH',         desc: '安全远程登录与命令执行', risk: 'medium' },
  23:   { name: 'Telnet',      desc: '明文远程登录，不安全', risk: 'high' },
  25:   { name: 'SMTP',        desc: '邮件发送服务', risk: 'low' },
  53:   { name: 'DNS',         desc: '域名解析服务', risk: 'low' },
  80:   { name: 'HTTP',        desc: 'Web 管理页面或网站服务', risk: 'low' },
  110:  { name: 'POP3',        desc: '邮件接收服务', risk: 'low' },
  135:  { name: 'RPC',         desc: 'Windows 远程过程调用', risk: 'medium' },
  139:  { name: 'NetBIOS',     desc: 'Windows 文件共享/名称服务', risk: 'medium' },
  143:  { name: 'IMAP',        desc: '邮件接收服务（同步）', risk: 'low' },
  443:  { name: 'HTTPS',       desc: '加密 Web 管理页面或网站服务', risk: 'low' },
  445:  { name: 'SMB',         desc: 'Windows 文件/打印机共享，易受攻击', risk: 'high' },
  993:  { name: 'IMAPS',       desc: '加密邮件接收服务', risk: 'low' },
  995:  { name: 'POP3S',       desc: '加密邮件接收服务', risk: 'low' },
  1900: { name: 'SSDP',        desc: 'UPnP 设备发现协议', risk: 'medium' },
  3306: { name: 'MySQL',       desc: 'MySQL 数据库服务', risk: 'high' },
  3389: { name: 'RDP',         desc: 'Windows 远程桌面连接', risk: 'medium' },
  5353: { name: 'mDNS',        desc: '组播 DNS（Bonjour/设备发现）', risk: 'low' },
  8080: { name: 'HTTP-Alt',    desc: '备用 Web 端口（代理/管理页）', risk: 'low' },
  8443: { name: 'HTTPS-Alt',   desc: '备用加密 Web 端口', risk: 'low' },
  9100: { name: 'Printer',     desc: '网络打印机 RAW 打印端口', risk: 'low' }
};

Scanner.OUI_DB = {
  // ── Apple ──
  'AC:DE:48': { vendor: 'Apple', category: 'phone' },
  '00:25:00': { vendor: 'Apple', category: 'computer' },
  'D0:E1:40': { vendor: 'Apple', category: 'computer' },
  'F0:18:98': { vendor: 'Apple', category: 'computer' },
  'F4:34:F0': { vendor: 'Apple', category: 'phone' },
  'F0:79:60': { vendor: 'Apple', category: 'computer' },
  'DC:A9:04': { vendor: 'Apple', category: 'computer' },
  '88:66:A5': { vendor: 'Apple', category: 'computer' },
  '04:D3:C0': { vendor: 'Apple', category: 'phone' },
  'A8:5C:2C': { vendor: 'Apple', category: 'phone' },
  '3C:22:FB': { vendor: 'Apple', category: 'phone' },
  '70:56:81': { vendor: 'Apple', category: 'phone' },
  '14:99:E2': { vendor: 'Apple', category: 'phone' },
  'B8:C7:5D': { vendor: 'Apple', category: 'computer' },
  'C8:69:CD': { vendor: 'Apple', category: 'computer' },
  '94:E9:79': { vendor: 'Apple', category: 'phone' },
  '20:EE:28': { vendor: 'Apple', category: 'computer' },
  '3C:06:30': { vendor: 'Apple', category: 'computer' },
  '00:16:CB': { vendor: 'Apple', category: 'computer' },
  '78:7B:8A': { vendor: 'Apple', category: 'phone' },
  '34:36:3B': { vendor: 'Apple', category: 'computer' },
  '5C:F7:E6': { vendor: 'Apple', category: 'computer' },
  '9C:20:7B': { vendor: 'Apple', category: 'phone' },

  // ── Samsung ──
  '00:12:47': { vendor: 'Samsung', category: 'phone' },
  '00:15:99': { vendor: 'Samsung', category: 'phone' },
  '00:16:32': { vendor: 'Samsung', category: 'phone' },
  '00:17:D5': { vendor: 'Samsung', category: 'phone' },
  '00:18:AF': { vendor: 'Samsung', category: 'phone' },
  '00:1A:8A': { vendor: 'Samsung', category: 'phone' },
  '00:1B:98': { vendor: 'Samsung', category: 'phone' },
  '00:1C:43': { vendor: 'Samsung', category: 'phone' },
  '00:1D:25': { vendor: 'Samsung', category: 'phone' },
  '00:1E:E1': { vendor: 'Samsung', category: 'phone' },
  '00:1E:E2': { vendor: 'Samsung', category: 'phone' },
  '00:21:4C': { vendor: 'Samsung', category: 'phone' },
  '00:21:D1': { vendor: 'Samsung', category: 'phone' },
  '00:21:D2': { vendor: 'Samsung', category: 'phone' },
  '00:23:39': { vendor: 'Samsung', category: 'phone' },
  '00:23:D6': { vendor: 'Samsung', category: 'phone' },
  '00:24:54': { vendor: 'Samsung', category: 'phone' },
  '00:24:90': { vendor: 'Samsung', category: 'phone' },
  '00:24:91': { vendor: 'Samsung', category: 'phone' },
  '00:25:66': { vendor: 'Samsung', category: 'phone' },
  '00:26:37': { vendor: 'Samsung', category: 'phone' },
  '00:26:5D': { vendor: 'Samsung', category: 'phone' },
  '10:D5:42': { vendor: 'Samsung', category: 'phone' },
  '24:4B:81': { vendor: 'Samsung', category: 'phone' },
  '30:96:FB': { vendor: 'Samsung', category: 'phone' },
  '34:23:BA': { vendor: 'Samsung', category: 'phone' },
  '34:C3:AC': { vendor: 'Samsung', category: 'phone' },
  '38:01:97': { vendor: 'Samsung', category: 'phone' },
  '38:0A:94': { vendor: 'Samsung', category: 'phone' },
  '40:0E:85': { vendor: 'Samsung', category: 'phone' },
  '40:4E:36': { vendor: 'Samsung', category: 'phone' },
  '44:4E:1A': { vendor: 'Samsung', category: 'phone' },
  '48:44:F7': { vendor: 'Samsung', category: 'phone' },
  '4C:B1:6C': { vendor: 'Samsung', category: 'phone' },
  '50:F5:20': { vendor: 'Samsung', category: 'phone' },
  '54:88:0E': { vendor: 'Samsung', category: 'phone' },
  '58:C3:8B': { vendor: 'Samsung', category: 'phone' },
  '5C:0A:5B': { vendor: 'Samsung', category: 'phone' },
  '60:6B:BD': { vendor: 'Samsung', category: 'phone' },
  '64:77:91': { vendor: 'Samsung', category: 'phone' },
  '68:27:37': { vendor: 'Samsung', category: 'phone' },
  '70:F9:27': { vendor: 'Samsung', category: 'phone' },
  '74:83:C2': { vendor: 'Samsung', category: 'phone' },
  '78:25:AD': { vendor: 'Samsung', category: 'phone' },
  '78:40:E4': { vendor: 'Samsung', category: 'phone' },
  '7C:0B:C6': { vendor: 'Samsung', category: 'phone' },
  '80:65:6D': { vendor: 'Samsung', category: 'phone' },
  '84:25:DB': { vendor: 'Samsung', category: 'phone' },
  '84:38:35': { vendor: 'Samsung', category: 'phone' },
  '84:A4:66': { vendor: 'Samsung', category: 'phone' },
  '84:B5:41': { vendor: 'Samsung', category: 'phone' },
  '84:B5:9C': { vendor: 'Samsung', category: 'phone' },
  '88:32:9B': { vendor: 'Samsung', category: 'phone' },
  '8C:71:F8': { vendor: 'Samsung', category: 'phone' },
  '90:18:7C': { vendor: 'Samsung', category: 'phone' },
  '90:F1:AA': { vendor: 'Samsung', category: 'phone' },
  '94:01:C2': { vendor: 'Samsung', category: 'phone' },
  '94:35:0A': { vendor: 'Samsung', category: 'phone' },
  '94:51:03': { vendor: 'Samsung', category: 'phone' },
  '94:B8:6D': { vendor: 'Samsung', category: 'phone' },
  '94:D7:71': { vendor: 'Samsung', category: 'phone' },
  '98:0C:82': { vendor: 'Samsung', category: 'phone' },
  '98:22:EF': { vendor: 'Samsung', category: 'phone' },
  '98:52:B1': { vendor: 'Samsung', category: 'phone' },
  '9C:02:98': { vendor: 'Samsung', category: 'phone' },
  '9C:3A:AF': { vendor: 'Samsung', category: 'phone' },
  'A0:07:98': { vendor: 'Samsung', category: 'phone' },
  'A0:0B:BA': { vendor: 'Samsung', category: 'phone' },
  'A0:82:1F': { vendor: 'Samsung', category: 'phone' },
  'A4:07:B6': { vendor: 'Samsung', category: 'phone' },
  'A8:06:00': { vendor: 'Samsung', category: 'phone' },
  'AC:36:13': { vendor: 'Samsung', category: 'phone' },
  'AC:5F:3E': { vendor: 'Samsung', category: 'phone' },
  'B0:47:BF': { vendor: 'Samsung', category: 'phone' },
  'B0:72:BF': { vendor: 'Samsung', category: 'phone' },
  'B4:3A:28': { vendor: 'Samsung', category: 'phone' },
  'B4:79:A7': { vendor: 'Samsung', category: 'phone' },
  'B4:EC:BF': { vendor: 'Samsung', category: 'phone' },
  'B8:27:EB': { vendor: 'Samsung', category: 'phone' },
  'BC:14:85': { vendor: 'Samsung', category: 'phone' },
  'BC:44:86': { vendor: 'Samsung', category: 'phone' },
  'BC:72:B1': { vendor: 'Samsung', category: 'phone' },
  'BC:B1:F3': { vendor: 'Samsung', category: 'phone' },
  'C0:97:27': { vendor: 'Samsung', category: 'phone' },
  'C0:BD:D1': { vendor: 'Samsung', category: 'phone' },
  'C0:BD:D2': { vendor: 'Samsung', category: 'phone' },
  'C4:42:02': { vendor: 'Samsung', category: 'phone' },
  'C4:73:1E': { vendor: 'Samsung', category: 'phone' },
  'C8:14:51': { vendor: 'Samsung', category: 'phone' },
  'C8:38:70': { vendor: 'Samsung', category: 'phone' },
  'CC:07:AB': { vendor: 'Samsung', category: 'phone' },
  'CC:3A:61': { vendor: 'Samsung', category: 'phone' },
  'D0:22:BE': { vendor: 'Samsung', category: 'phone' },
  'D0:25:98': { vendor: 'Samsung', category: 'phone' },
  'D0:59:E4': { vendor: 'Samsung', category: 'phone' },
  'D0:87:E2': { vendor: 'Samsung', category: 'phone' },
  'D4:88:90': { vendor: 'Samsung', category: 'phone' },
  'D8:57:EF': { vendor: 'Samsung', category: 'phone' },
  'DC:45:46': { vendor: 'Samsung', category: 'phone' },
  'E0:99:71': { vendor: 'Samsung', category: 'phone' },
  'E0:CB:EE': { vendor: 'Samsung', category: 'phone' },
  'E4:12:1D': { vendor: 'Samsung', category: 'phone' },
  'E4:7C:F9': { vendor: 'Samsung', category: 'phone' },
  'E4:92:FB': { vendor: 'Samsung', category: 'phone' },
  'E4:BB:DD': { vendor: 'Samsung', category: 'phone' },
  'E8:03:9A': { vendor: 'Samsung', category: 'phone' },
  'E8:50:8B': { vendor: 'Samsung', category: 'phone' },
  'EC:1F:72': { vendor: 'Samsung', category: 'phone' },
  'EC:9B:F3': { vendor: 'Samsung', category: 'phone' },
  'F0:08:F1': { vendor: 'Samsung', category: 'phone' },
  'F0:25:B7': { vendor: 'Samsung', category: 'phone' },
  'F0:5A:09': { vendor: 'Samsung', category: 'phone' },
  'F0:D7:AA': { vendor: 'Samsung', category: 'phone' },
  'F4:09:D8': { vendor: 'Samsung', category: 'phone' },
  'F4:42:8F': { vendor: 'Samsung', category: 'phone' },
  'F4:7B:5E': { vendor: 'Samsung', category: 'phone' },
  'F4:9F:F3': { vendor: 'Samsung', category: 'phone' },
  'FC:F1:36': { vendor: 'Samsung', category: 'phone' },
  'FC:A1:3E': { vendor: 'Samsung', category: 'phone' },

  // ── Huawei ──
  '00:E0:FC': { vendor: 'Huawei', category: 'router' },
  '28:6C:07': { vendor: 'Huawei', category: 'router' },
  '24:DF:A7': { vendor: 'Huawei', category: 'phone' },
  '48:46:FB': { vendor: 'Huawei', category: 'phone' },
  '48:AD:16': { vendor: 'Huawei', category: 'phone' },
  '4C:B1:6C': { vendor: 'Huawei', category: 'phone' },
  '5C:09:79': { vendor: 'Huawei', category: 'phone' },
  '5C:C3:07': { vendor: 'Huawei', category: 'phone' },
  '60:08:10': { vendor: 'Huawei', category: 'phone' },
  '60:DE:44': { vendor: 'Huawei', category: 'phone' },
  '68:A0:F6': { vendor: 'Huawei', category: 'phone' },
  '70:19:2F': { vendor: 'Huawei', category: 'phone' },
  '70:72:3C': { vendor: 'Huawei', category: 'phone' },
  '70:8A:09': { vendor: 'Huawei', category: 'phone' },
  '70:A8:E3': { vendor: 'Huawei', category: 'phone' },
  '74:88:2A': { vendor: 'Huawei', category: 'phone' },
  '78:6A:89': { vendor: 'Huawei', category: 'phone' },
  '78:D7:52': { vendor: 'Huawei', category: 'phone' },
  '80:38:BC': { vendor: 'Huawei', category: 'phone' },
  '80:71:79': { vendor: 'Huawei', category: 'phone' },
  '84:5B:12': { vendor: 'Huawei', category: 'phone' },
  '84:A8:E4': { vendor: 'Huawei', category: 'phone' },
  '88:3F:D3': { vendor: 'Huawei', category: 'phone' },
  '88:53:D4': { vendor: 'Huawei', category: 'phone' },
  '88:66:39': { vendor: 'Huawei', category: 'phone' },
  '88:CF:98': { vendor: 'Huawei', category: 'phone' },
  '88:E3:AB': { vendor: 'Huawei', category: 'phone' },
  '8C:F5:A3': { vendor: 'Huawei', category: 'phone' },
  '90:17:AC': { vendor: 'Huawei', category: 'phone' },
  '90:4E:2B': { vendor: 'Huawei', category: 'phone' },
  '94:04:9C': { vendor: 'Huawei', category: 'phone' },
  '94:77:2B': { vendor: 'Huawei', category: 'phone' },
  '94:DB:C9': { vendor: 'Huawei', category: 'phone' },
  '94:FE:22': { vendor: 'Huawei', category: 'phone' },
  '98:E7:F4': { vendor: 'Huawei', category: 'phone' },
  '9C:28:EF': { vendor: 'Huawei', category: 'phone' },
  '9C:B2:B2': { vendor: 'Huawei', category: 'phone' },
  'A0:57:E3': { vendor: 'Huawei', category: 'phone' },
  'A0:8C:F8': { vendor: 'Huawei', category: 'phone' },
  'A4:99:47': { vendor: 'Huawei', category: 'phone' },
  'A4:DC:BE': { vendor: 'Huawei', category: 'phone' },
  'AC:4E:91': { vendor: 'Huawei', category: 'phone' },
  'AC:61:EA': { vendor: 'Huawei', category: 'phone' },
  'AC:CF:85': { vendor: 'Huawei', category: 'phone' },
  'B0:5B:67': { vendor: 'Huawei', category: 'phone' },
  'B4:15:13': { vendor: 'Huawei', category: 'phone' },
  'B4:30:52': { vendor: 'Huawei', category: 'phone' },
  'B8:BC:1B': { vendor: 'Huawei', category: 'phone' },
  'C0:70:09': { vendor: 'Huawei', category: 'phone' },
  'C0:72:BC': { vendor: 'Huawei', category: 'phone' },
  'C4:05:28': { vendor: 'Huawei', category: 'phone' },
  'C4:07:2F': { vendor: 'Huawei', category: 'phone' },
  'C8:51:95': { vendor: 'Huawei', category: 'phone' },
  'CC:53:B5': { vendor: 'Huawei', category: 'phone' },
  'CC:96:A0': { vendor: 'Huawei', category: 'phone' },
  'CC:CC:81': { vendor: 'Huawei', category: 'phone' },
  'D0:2D:B3': { vendor: 'Huawei', category: 'phone' },
  'D0:7A:B5': { vendor: 'Huawei', category: 'phone' },
  'D4:40:F5': { vendor: 'Huawei', category: 'phone' },
  'D4:6A:A8': { vendor: 'Huawei', category: 'phone' },
  'D4:6E:5C': { vendor: 'Huawei', category: 'phone' },
  'D8:49:0B': { vendor: 'Huawei', category: 'phone' },
  'DC:09:4C': { vendor: 'Huawei', category: 'phone' },
  'DC:D2:FC': { vendor: 'Huawei', category: 'phone' },
  'E0:19:1D': { vendor: 'Huawei', category: 'phone' },
  'E0:24:7F': { vendor: 'Huawei', category: 'phone' },
  'E0:36:76': { vendor: 'Huawei', category: 'phone' },
  'E0:97:96': { vendor: 'Huawei', category: 'phone' },
  'E4:68:A3': { vendor: 'Huawei', category: 'phone' },
  'E4:7E:66': { vendor: 'Huawei', category: 'phone' },
  'E4:C2:D1': { vendor: 'Huawei', category: 'phone' },
  'E8:08:8B': { vendor: 'Huawei', category: 'phone' },
  'E8:68:19': { vendor: 'Huawei', category: 'phone' },
  'E8:CD:2D': { vendor: 'Huawei', category: 'phone' },
  'EC:23:3D': { vendor: 'Huawei', category: 'phone' },
  'EC:38:8F': { vendor: 'Huawei', category: 'phone' },
  'EC:CB:30': { vendor: 'Huawei', category: 'phone' },
  'F0:18:2C': { vendor: 'Huawei', category: 'phone' },
  'F0:24:7D': { vendor: 'Huawei', category: 'phone' },
  'F0:43:47': { vendor: 'Huawei', category: 'phone' },
  'F0:A7:31': { vendor: 'Huawei', category: 'phone' },
  'F0:F0:04': { vendor: 'Huawei', category: 'phone' },
  'F4:55:9C': { vendor: 'Huawei', category: 'phone' },
  'F4:63:1F': { vendor: 'Huawei', category: 'phone' },
  'F4:9F:F3': { vendor: 'Huawei', category: 'phone' },
  'F8:01:13': { vendor: 'Huawei', category: 'phone' },
  'F8:3D:FF': { vendor: 'Huawei', category: 'phone' },
  'F8:4A:BF': { vendor: 'Huawei', category: 'phone' },
  'F8:E8:11': { vendor: 'Huawei', category: 'phone' },
  'FC:48:EF': { vendor: 'Huawei', category: 'phone' },

  // ── Xiaomi / Redmi / Aqara ──
  '18:B4:30': { vendor: 'Xiaomi', category: 'iot' },
  '64:69:4E': { vendor: 'Xiaomi', category: 'phone' },
  '7C:49:EB': { vendor: 'Xiaomi', category: 'phone' },
  '9C:99:A0': { vendor: 'Xiaomi', category: 'phone' },
  '28:6C:07': { vendor: 'Xiaomi', category: 'phone' },
  '34:80:B3': { vendor: 'Xiaomi', category: 'phone' },
  '50:64:2B': { vendor: 'Xiaomi', category: 'phone' },
  '58:44:98': { vendor: 'Xiaomi', category: 'phone' },
  '5C:E0:C5': { vendor: 'Xiaomi', category: 'phone' },
  '64:B4:73': { vendor: 'Xiaomi', category: 'phone' },
  '68:3B:78': { vendor: 'Xiaomi', category: 'phone' },
  '6C:A1:00': { vendor: 'Xiaomi', category: 'phone' },
  '70:5D:EF': { vendor: 'Xiaomi', category: 'phone' },
  '74:23:44': { vendor: 'Xiaomi', category: 'phone' },
  '74:51:BA': { vendor: 'Xiaomi', category: 'phone' },
  '74:BD:05': { vendor: 'Xiaomi', category: 'phone' },
  '78:11:DC': { vendor: 'Xiaomi', category: 'phone' },
  '78:90:B2': { vendor: 'Xiaomi', category: 'phone' },
  '7C:78:B2': { vendor: 'Xiaomi', category: 'phone' },
  '7C:C7:09': { vendor: 'Xiaomi', category: 'phone' },
  '80:69:33': { vendor: 'Xiaomi', category: 'phone' },
  '84:A9:3E': { vendor: 'Xiaomi', category: 'phone' },
  '88:C3:97': { vendor: 'Xiaomi', category: 'phone' },
  '8C:BE:BE': { vendor: 'Xiaomi', category: 'phone' },
  '90:A2:DA': { vendor: 'Xiaomi', category: 'phone' },
  '94:B9:7E': { vendor: 'Xiaomi', category: 'phone' },
  '94:C9:37': { vendor: 'Xiaomi', category: 'phone' },
  '98:FA:9B': { vendor: 'Xiaomi', category: 'phone' },
  '9C:53:22': { vendor: 'Xiaomi', category: 'phone' },
  'A0:86:C6': { vendor: 'Xiaomi', category: 'phone' },
  'A4:08:EA': { vendor: 'Xiaomi', category: 'phone' },
  'A4:4C:9A': { vendor: 'Xiaomi', category: 'phone' },
  'AC:F7:F3': { vendor: 'Xiaomi', category: 'phone' },
  'B0:E2:35': { vendor: 'Xiaomi', category: 'phone' },
  'B0:E3:B5': { vendor: 'Xiaomi', category: 'router' },
  'C0:EE:40': { vendor: 'Xiaomi', category: 'phone' },
  'C4:6A:B7': { vendor: 'Xiaomi', category: 'phone' },
  'C8:3A:35': { vendor: 'Xiaomi', category: 'phone' },
  'CC:1D:EC': { vendor: 'Xiaomi', category: 'phone' },
  'D0:2A:74': { vendor: 'Xiaomi', category: 'phone' },
  'D0:BD:5C': { vendor: 'Xiaomi', category: 'phone' },
  'D4:97:0B': { vendor: 'Xiaomi', category: 'phone' },
  'D4:9A:3C': { vendor: 'Xiaomi', category: 'phone' },
  'DC:00:B0': { vendor: 'Xiaomi', category: 'phone' },
  'E0:5F:B9': { vendor: 'Xiaomi', category: 'phone' },
  'E4:46:3B': { vendor: 'Xiaomi', category: 'phone' },
  'E8:3E:FB': { vendor: 'Xiaomi', category: 'phone' },
  'EC:FA:BC': { vendor: 'Xiaomi', category: 'phone' },
  'F0:B4:29': { vendor: 'Xiaomi', category: 'phone' },
  'F0:B4:D2': { vendor: 'Xiaomi', category: 'phone' },
  'F4:8C:50': { vendor: 'Xiaomi', category: 'phone' },
  'F4:A5:2B': { vendor: 'Xiaomi', category: 'phone' },
  'F4:F5:E8': { vendor: 'Xiaomi', category: 'phone' },
  'F8:A4:5F': { vendor: 'Xiaomi', category: 'phone' },
  'FC:64:B2': { vendor: 'Xiaomi', category: 'phone' },
  'FC:F9:EF': { vendor: 'Xiaomi', category: 'phone' },

  // ── OPPO / OnePlus / realme ──
  '00:12:1C': { vendor: 'OPPO', category: 'phone' },
  '10:CC:81': { vendor: 'OPPO', category: 'phone' },
  '14:3C:C6': { vendor: 'OPPO', category: 'phone' },
  '18:65:CD': { vendor: 'OPPO', category: 'phone' },
  '20:5D:47': { vendor: 'OPPO', category: 'phone' },
  '24:0A:C4': { vendor: 'OPPO', category: 'phone' },
  '28:A1:83': { vendor: 'OPPO', category: 'phone' },
  '2C:4D:54': { vendor: 'OPPO', category: 'phone' },
  '30:FD:38': { vendor: 'OPPO', category: 'phone' },
  '34:29:12': { vendor: 'OPPO', category: 'phone' },
  '34:E0:CF': { vendor: 'OPPO', category: 'phone' },
  '38:01:9F': { vendor: 'OPPO', category: 'phone' },
  '38:F8:89': { vendor: 'OPPO', category: 'phone' },
  '40:EC:99': { vendor: 'OPPO', category: 'phone' },
  '44:82:EB': { vendor: 'OPPO', category: 'phone' },
  '48:35:2E': { vendor: 'OPPO', category: 'phone' },
  '4C:ED:FB': { vendor: 'OPPO', category: 'phone' },
  '50:2B:73': { vendor: 'OPPO', category: 'phone' },
  '54:A6:5C': { vendor: 'OPPO', category: 'phone' },
  '58:0C:F7': { vendor: 'OPPO', category: 'phone' },
  '5C:3A:45': { vendor: 'OPPO', category: 'phone' },
  '60:9F:2D': { vendor: 'OPPO', category: 'phone' },
  '64:5E:C8': { vendor: 'OPPO', category: 'phone' },
  '68:20:05': { vendor: 'OPPO', category: 'phone' },
  '6C:5D:63': { vendor: 'OPPO', category: 'phone' },
  '70:18:A3': { vendor: 'OPPO', category: 'phone' },
  '74:12:B3': { vendor: 'OPPO', category: 'phone' },
  '78:25:AD': { vendor: 'OPPO', category: 'phone' },
  '78:B8:4F': { vendor: 'OPPO', category: 'phone' },
  '7C:64:6C': { vendor: 'OPPO', category: 'phone' },
  '80:5A:04': { vendor: 'OPPO', category: 'phone' },
  '84:A9:3E': { vendor: 'OPPO', category: 'phone' },
  '88:28:B3': { vendor: 'OPPO', category: 'phone' },
  '8C:49:32': { vendor: 'OPPO', category: 'phone' },
  '90:21:06': { vendor: 'OPPO', category: 'phone' },
  '94:35:0A': { vendor: 'OPPO', category: 'phone' },
  '94:B8:6D': { vendor: 'OPPO', category: 'phone' },
  '98:13:43': { vendor: 'OPPO', category: 'phone' },
  '98:D8:31': { vendor: 'OPPO', category: 'phone' },
  'A0:60:32': { vendor: 'OPPO', category: 'phone' },
  'A4:28:B7': { vendor: 'OPPO', category: 'phone' },
  'A8:57:02': { vendor: 'OPPO', category: 'phone' },
  'AC:BC:32': { vendor: 'OPPO', category: 'phone' },
  'B0:AA:77': { vendor: 'OPPO', category: 'phone' },
  'B4:45:06': { vendor: 'OPPO', category: 'phone' },
  'B8:37:18': { vendor: 'OPPO', category: 'phone' },
  'BC:3B:AF': { vendor: 'OPPO', category: 'phone' },
  'C0:EE:40': { vendor: 'OPPO', category: 'phone' },
  'C4:27:89': { vendor: 'OPPO', category: 'phone' },
  'C8:2E:47': { vendor: 'OPPO', category: 'phone' },
  'CC:0E:97': { vendor: 'OPPO', category: 'phone' },
  'D0:46:F0': { vendor: 'OPPO', category: 'phone' },
  'D4:3D:2E': { vendor: 'OPPO', category: 'phone' },
  'D8:0C:CB': { vendor: 'OPPO', category: 'phone' },
  'DC:2C:6E': { vendor: 'OPPO', category: 'phone' },
  'E0:4F:43': { vendor: 'OPPO', category: 'phone' },
  'E4:38:0C': { vendor: 'OPPO', category: 'phone' },
  'E8:48:B8': { vendor: 'OPPO', category: 'phone' },
  'EC:1C:68': { vendor: 'OPPO', category: 'phone' },
  'F0:1D:BC': { vendor: 'OPPO', category: 'phone' },
  'F4:4E:FD': { vendor: 'OPPO', category: 'phone' },
  'F8:62:AA': { vendor: 'OPPO', category: 'phone' },
  'FC:44:82': { vendor: 'OPPO', category: 'phone' },

  // ── vivo ──
  '00:E0:4C': { vendor: 'vivo', category: 'phone' },
  '24:0A:C4': { vendor: 'vivo', category: 'phone' },
  '30:FD:38': { vendor: 'vivo', category: 'phone' },
  '40:E3:D6': { vendor: 'vivo', category: 'phone' },
  '48:0D:BF': { vendor: 'vivo', category: 'phone' },
  '4C:ED:FB': { vendor: 'vivo', category: 'phone' },
  '5C:51:81': { vendor: 'vivo', category: 'phone' },
  '60:9F:2D': { vendor: 'vivo', category: 'phone' },
  '64:17:5F': { vendor: 'vivo', category: 'phone' },
  '68:3B:78': { vendor: 'vivo', category: 'phone' },
  '6C:5D:63': { vendor: 'vivo', category: 'phone' },
  '70:18:A3': { vendor: 'vivo', category: 'phone' },
  '74:12:B3': { vendor: 'vivo', category: 'phone' },
  '78:25:AD': { vendor: 'vivo', category: 'phone' },
  '78:B8:4F': { vendor: 'vivo', category: 'phone' },
  '7C:64:6C': { vendor: 'vivo', category: 'phone' },
  '80:5A:04': { vendor: 'vivo', category: 'phone' },
  '84:A9:3E': { vendor: 'vivo', category: 'phone' },
  '88:28:B3': { vendor: 'vivo', category: 'phone' },
  '8C:49:32': { vendor: 'vivo', category: 'phone' },
  '90:21:06': { vendor: 'vivo', category: 'phone' },
  '94:35:0A': { vendor: 'vivo', category: 'phone' },
  '94:B8:6D': { vendor: 'vivo', category: 'phone' },
  '98:13:43': { vendor: 'vivo', category: 'phone' },
  '98:D8:31': { vendor: 'vivo', category: 'phone' },
  'A0:60:32': { vendor: 'vivo', category: 'phone' },
  'A4:28:B7': { vendor: 'vivo', category: 'phone' },
  'A8:57:02': { vendor: 'vivo', category: 'phone' },
  'AC:BC:32': { vendor: 'vivo', category: 'phone' },
  'B0:AA:77': { vendor: 'vivo', category: 'phone' },
  'B4:45:06': { vendor: 'vivo', category: 'phone' },
  'B8:37:18': { vendor: 'vivo', category: 'phone' },
  'BC:3B:AF': { vendor: 'vivo', category: 'phone' },
  'C0:EE:40': { vendor: 'vivo', category: 'phone' },
  'C4:27:89': { vendor: 'vivo', category: 'phone' },
  'C8:2E:47': { vendor: 'vivo', category: 'phone' },
  'CC:0E:97': { vendor: 'vivo', category: 'phone' },
  'D0:46:F0': { vendor: 'vivo', category: 'phone' },
  'D4:3D:2E': { vendor: 'vivo', category: 'phone' },
  'D8:0C:CB': { vendor: 'vivo', category: 'phone' },
  'DC:2C:6E': { vendor: 'vivo', category: 'phone' },
  'E0:4F:43': { vendor: 'vivo', category: 'phone' },
  'E4:38:0C': { vendor: 'vivo', category: 'phone' },
  'E8:48:B8': { vendor: 'vivo', category: 'phone' },
  'EC:1C:68': { vendor: 'vivo', category: 'phone' },
  'F0:1D:BC': { vendor: 'vivo', category: 'phone' },
  'F4:4E:FD': { vendor: 'vivo', category: 'phone' },
  'F8:62:AA': { vendor: 'vivo', category: 'phone' },
  'FC:44:82': { vendor: 'vivo', category: 'phone' },

  // ── Google / Pixel ──
  '00:1A:11': { vendor: 'Google', category: 'phone' },
  '3C:5A:B4': { vendor: 'Google', category: 'phone' },
  '94:EB:2C': { vendor: 'Google', category: 'phone' },
  'A4:77:33': { vendor: 'Google', category: 'phone' },
  'F4:F5:E8': { vendor: 'Google', category: 'phone' },
  '54:60:09': { vendor: 'Google', category: 'phone' },
  '3C:28:6D': { vendor: 'Google', category: 'iot' },
  '68:37:E9': { vendor: 'Google', category: 'iot' },
  'A4:60:32': { vendor: 'Google', category: 'phone' },
  'D8:31:CF': { vendor: 'Google', category: 'phone' },
  '28:6C:07': { vendor: 'Google', category: 'phone' },

  // ── Lenovo / Motorola ──
  '00:06:1B': { vendor: 'Lenovo', category: 'computer' },
  '00:08:C7': { vendor: 'Lenovo', category: 'computer' },
  '00:0E:8F': { vendor: 'Lenovo', category: 'computer' },
  '00:10:F1': { vendor: 'Lenovo', category: 'computer' },
  '00:15:AD': { vendor: 'Lenovo', category: 'computer' },
  '00:16:00': { vendor: 'Lenovo', category: 'computer' },
  '00:17:FA': { vendor: 'Lenovo', category: 'computer' },
  '00:18:DE': { vendor: 'Lenovo', category: 'computer' },
  '00:19:AA': { vendor: 'Lenovo', category: 'computer' },
  '00:1A:2B': { vendor: 'Lenovo', category: 'computer' },
  '00:1B:38': { vendor: 'Lenovo', category: 'computer' },
  '00:1C:5A': { vendor: 'Lenovo', category: 'computer' },
  '00:1D:0D': { vendor: 'Lenovo', category: 'computer' },
  '00:1E:49': { vendor: 'Lenovo', category: 'computer' },
  '00:21:70': { vendor: 'Lenovo', category: 'computer' },
  '00:22:72': { vendor: 'Lenovo', category: 'computer' },
  '00:23:24': { vendor: 'Lenovo', category: 'computer' },
  '00:24:D6': { vendor: 'Lenovo', category: 'computer' },
  '00:25:64': { vendor: 'Lenovo', category: 'computer' },
  '00:26:C7': { vendor: 'Lenovo', category: 'computer' },
  '00:8E:32': { vendor: 'Lenovo', category: 'computer' },
  '04:F1:3E': { vendor: 'Lenovo', category: 'computer' },
  '08:D2:9E': { vendor: 'Lenovo', category: 'computer' },
  '10:1F:74': { vendor: 'Lenovo', category: 'computer' },
  '18:AF:61': { vendor: 'Lenovo', category: 'computer' },
  '1C:39:7A': { vendor: 'Lenovo', category: 'computer' },
  '20:6B:E7': { vendor: 'Lenovo', category: 'computer' },
  '24:B6:57': { vendor: 'Lenovo', category: 'computer' },
  '28:D2:44': { vendor: 'Lenovo', category: 'computer' },
  '2C:58:B9': { vendor: 'Lenovo', category: 'computer' },
  '30:D0:42': { vendor: 'Lenovo', category: 'computer' },
  '34:02:86': { vendor: 'Lenovo', category: 'computer' },
  '34:97:F6': { vendor: 'Lenovo', category: 'computer' },
  '38:22:D6': { vendor: 'Lenovo', category: 'computer' },
  '3C:97:0E': { vendor: 'Lenovo', category: 'computer' },
  '40:78:B6': { vendor: 'Lenovo', category: 'computer' },
  '44:38:39': { vendor: 'Lenovo', category: 'computer' },
  '48:2A:E3': { vendor: 'Lenovo', category: 'computer' },
  '4C:CC:6A': { vendor: 'Lenovo', category: 'computer' },
  '50:5B:C2': { vendor: 'Lenovo', category: 'computer' },
  '54:EE:75': { vendor: 'Lenovo', category: 'computer' },
  '58:8A:5A': { vendor: 'Lenovo', category: 'computer' },
  '5C:E0:C5': { vendor: 'Lenovo', category: 'computer' },
  '60:D8:19': { vendor: 'Lenovo', category: 'computer' },
  '64:5A:ED': { vendor: 'Lenovo', category: 'computer' },
  '68:F7:15': { vendor: 'Lenovo', category: 'computer' },
  '6C:C3:74': { vendor: 'Lenovo', category: 'computer' },
  '70:1A:B4': { vendor: 'Lenovo', category: 'computer' },
  '70:5A:0F': { vendor: 'Lenovo', category: 'computer' },
  '74:40:BE': { vendor: 'Lenovo', category: 'computer' },
  '78:E7:D1': { vendor: 'Lenovo', category: 'computer' },
  '7C:4C:A5': { vendor: 'Lenovo', category: 'computer' },
  '80:CE:62': { vendor: 'Lenovo', category: 'computer' },
  '84:3F:3E': { vendor: 'Lenovo', category: 'computer' },
  '88:71:B1': { vendor: 'Lenovo', category: 'computer' },
  '8C:EC:4B': { vendor: 'Lenovo', category: 'computer' },
  '90:61:AE': { vendor: 'Lenovo', category: 'computer' },
  '94:39:E6': { vendor: 'Lenovo', category: 'computer' },
  '94:DE:80': { vendor: 'Lenovo', category: 'computer' },
  '98:FA:9B': { vendor: 'Lenovo', category: 'computer' },
  '9C:5C:F9': { vendor: 'Lenovo', category: 'computer' },
  'A4:34:D9': { vendor: 'Lenovo', category: 'computer' },
  'A4:4C:C8': { vendor: 'Lenovo', category: 'computer' },
  'A4:90:05': { vendor: 'Lenovo', category: 'computer' },
  'AC:61:EA': { vendor: 'Lenovo', category: 'computer' },
  'AC:87:A3': { vendor: 'Lenovo', category: 'computer' },
  'B0:83:FE': { vendor: 'Lenovo', category: 'computer' },
  'B4:70:0C': { vendor: 'Lenovo', category: 'computer' },
  'B4:99:BA': { vendor: 'Lenovo', category: 'computer' },
  'B8:03:05': { vendor: 'Lenovo', category: 'computer' },
  'B8:8A:EC': { vendor: 'Lenovo', category: 'computer' },
  'C0:38:96': { vendor: 'Lenovo', category: 'computer' },
  'C4:5E:7C': { vendor: 'Lenovo', category: 'computer' },
  'C8:5B:76': { vendor: 'Lenovo', category: 'computer' },
  'CC:3D:82': { vendor: 'Lenovo', category: 'computer' },
  'CC:AF:78': { vendor: 'Lenovo', category: 'computer' },
  'D0:57:4B': { vendor: 'Lenovo', category: 'computer' },
  'D0:63:B4': { vendor: 'Lenovo', category: 'computer' },
  'D4:3D:7E': { vendor: 'Lenovo', category: 'computer' },
  'D8:D0:90': { vendor: 'Lenovo', category: 'computer' },
  'DC:2C:6E': { vendor: 'Lenovo', category: 'computer' },
  'E0:1F:88': { vendor: 'Lenovo', category: 'computer' },
  'E0:99:71': { vendor: 'Lenovo', category: 'computer' },
  'E4:47:90': { vendor: 'Lenovo', category: 'computer' },
  'E8:2A:44': { vendor: 'Lenovo', category: 'computer' },
  'EC:5C:68': { vendor: 'Lenovo', category: 'computer' },
  'F0:1B:AF': { vendor: 'Lenovo', category: 'computer' },
  'F0:DE:F1': { vendor: 'Lenovo', category: 'computer' },
  'F4:EE:08': { vendor: 'Lenovo', category: 'computer' },
  'F8:2F:D0': { vendor: 'Lenovo', category: 'computer' },
  'FC:3F:DB': { vendor: 'Lenovo', category: 'computer' },

  // ── Dell ──
  '18:81:0A': { vendor: 'Dell', category: 'computer' },
  '5C:26:0A': { vendor: 'Dell', category: 'computer' },
  '74:E6:E2': { vendor: 'Dell', category: 'computer' },
  'D4:BE:D9': { vendor: 'Dell', category: 'computer' },
  '00:06:5B': { vendor: 'Dell', category: 'computer' },
  '00:08:74': { vendor: 'Dell', category: 'computer' },
  '00:0B:DB': { vendor: 'Dell', category: 'computer' },
  '00:0D:56': { vendor: 'Dell', category: 'computer' },
  '00:0F:1F': { vendor: 'Dell', category: 'computer' },
  '00:11:43': { vendor: 'Dell', category: 'computer' },
  '00:12:3F': { vendor: 'Dell', category: 'computer' },
  '00:13:72': { vendor: 'Dell', category: 'computer' },
  '00:14:22': { vendor: 'Dell', category: 'computer' },
  '00:15:C5': { vendor: 'Dell', category: 'computer' },
  '00:16:35': { vendor: 'Dell', category: 'computer' },
  '00:18:8B': { vendor: 'Dell', category: 'computer' },
  '00:19:B9': { vendor: 'Dell', category: 'computer' },
  '00:1A:A0': { vendor: 'Dell', category: 'computer' },
  '00:1B:24': { vendor: 'Dell', category: 'computer' },
  '00:1C:23': { vendor: 'Dell', category: 'computer' },
  '00:1D:09': { vendor: 'Dell', category: 'computer' },
  '00:1E:4F': { vendor: 'Dell', category: 'computer' },
  '00:1F:33': { vendor: 'Dell', category: 'computer' },
  '00:20:AA': { vendor: 'Dell', category: 'computer' },
  '00:21:9B': { vendor: 'Dell', category: 'computer' },
  '00:22:19': { vendor: 'Dell', category: 'computer' },
  '00:23:18': { vendor: 'Dell', category: 'computer' },
  '00:24:E8': { vendor: 'Dell', category: 'computer' },
  '00:25:64': { vendor: 'Dell', category: 'computer' },
  '00:26:5A': { vendor: 'Dell', category: 'computer' },
  'B0:83:FE': { vendor: 'Dell', category: 'computer' },
  'C4:34:6B': { vendor: 'Dell', category: 'computer' },
  'D0:94:66': { vendor: 'Dell', category: 'computer' },
  'F8:BC:12': { vendor: 'Dell', category: 'computer' },

  // ── HP ──
  '00:01:02': { vendor: 'HP', category: 'computer' },
  '00:02:A5': { vendor: 'HP', category: 'computer' },
  '00:04:EA': { vendor: 'HP', category: 'computer' },
  '00:06:0B': { vendor: 'HP', category: 'computer' },
  '00:08:22': { vendor: 'HP', category: 'computer' },
  '00:0B:CD': { vendor: 'HP', category: 'computer' },
  '00:0D:9D': { vendor: 'HP', category: 'computer' },
  '00:0E:7F': { vendor: 'HP', category: 'computer' },
  '00:10:83': { vendor: 'HP', category: 'computer' },
  '00:11:0A': { vendor: 'HP', category: 'computer' },
  '00:12:79': { vendor: 'HP', category: 'computer' },
  '00:13:21': { vendor: 'HP', category: 'computer' },
  '00:14:38': { vendor: 'HP', category: 'computer' },
  '00:15:60': { vendor: 'HP', category: 'computer' },
  '00:16:35': { vendor: 'HP', category: 'computer' },
  '00:17:A4': { vendor: 'HP', category: 'computer' },
  '00:18:FE': { vendor: 'HP', category: 'computer' },
  '00:19:BB': { vendor: 'HP', category: 'computer' },
  '00:1A:4B': { vendor: 'HP', category: 'computer' },
  '00:1B:78': { vendor: 'HP', category: 'computer' },
  '00:1C:C4': { vendor: 'HP', category: 'computer' },
  '00:1D:28': { vendor: 'HP', category: 'computer' },
  '00:1E:0B': { vendor: 'HP', category: 'computer' },
  '00:1F:29': { vendor: 'HP', category: 'computer' },
  '00:20:7A': { vendor: 'HP', category: 'computer' },
  '00:21:5A': { vendor: 'HP', category: 'computer' },
  '00:22:64': { vendor: 'HP', category: 'computer' },
  '00:23:7D': { vendor: 'HP', category: 'computer' },
  '00:24:81': { vendor: 'HP', category: 'computer' },
  '00:25:B3': { vendor: 'HP', category: 'computer' },
  '00:26:BB': { vendor: 'HP', category: 'computer' },

  // ── ASUS ──
  '00:0C:6E': { vendor: 'ASUS', category: 'computer' },
  '00:0E:A6': { vendor: 'ASUS', category: 'computer' },
  '00:11:2F': { vendor: 'ASUS', category: 'computer' },
  '00:13:D4': { vendor: 'ASUS', category: 'computer' },
  '00:15:F2': { vendor: 'ASUS', category: 'computer' },
  '00:17:7D': { vendor: 'ASUS', category: 'computer' },
  '00:19:99': { vendor: 'ASUS', category: 'computer' },
  '00:1B:B2': { vendor: 'ASUS', category: 'computer' },
  '00:1D:60': { vendor: 'ASUS', category: 'computer' },
  '00:1E:8C': { vendor: 'ASUS', category: 'computer' },
  '00:22:15': { vendor: 'ASUS', category: 'computer' },
  '00:23:54': { vendor: 'ASUS', category: 'computer' },
  '00:24:8C': { vendor: 'ASUS', category: 'computer' },
  '00:25:22': { vendor: 'ASUS', category: 'computer' },
  '00:26:18': { vendor: 'ASUS', category: 'computer' },
  '04:D4:C4': { vendor: 'ASUS', category: 'computer' },
  '08:62:66': { vendor: 'ASUS', category: 'computer' },
  '10:BF:48': { vendor: 'ASUS', category: 'computer' },
  '14:DA:E9': { vendor: 'ASUS', category: 'computer' },
  '1C:87:2C': { vendor: 'ASUS', category: 'computer' },
  '20:CF:30': { vendor: 'ASUS', category: 'computer' },
  '24:4B:FE': { vendor: 'ASUS', category: 'computer' },
  '2C:FD:A1': { vendor: 'ASUS', category: 'computer' },
  '30:5A:3A': { vendor: 'ASUS', category: 'computer' },
  '34:97:F6': { vendor: 'ASUS', category: 'computer' },
  '38:D5:47': { vendor: 'ASUS', category: 'computer' },
  '3C:88:00': { vendor: 'ASUS', category: 'computer' },
  '40:16:7E': { vendor: 'ASUS', category: 'computer' },
  '44:65:0D': { vendor: 'ASUS', category: 'computer' },
  '48:EE:0C': { vendor: 'ASUS', category: 'computer' },
  '4C:ED:FB': { vendor: 'ASUS', category: 'computer' },
  '50:46:5D': { vendor: 'ASUS', category: 'computer' },
  '54:04:A6': { vendor: 'ASUS', category: 'computer' },
  '58:11:43': { vendor: 'ASUS', category: 'computer' },
  '5C:CF:7F': { vendor: 'ASUS', category: 'computer' },
  '60:45:CB': { vendor: 'ASUS', category: 'computer' },
  '60:63:4C': { vendor: 'ASUS', category: 'computer' },
  '64:D9:54': { vendor: 'ASUS', category: 'computer' },
  '68:17:29': { vendor: 'ASUS', category: 'computer' },
  '70:85:C2': { vendor: 'ASUS', category: 'computer' },
  '74:D0:2B': { vendor: 'ASUS', category: 'computer' },
  '78:54:1E': { vendor: 'ASUS', category: 'computer' },
  '7C:8B:CA': { vendor: 'ASUS', category: 'computer' },
  '80:81:A5': { vendor: 'ASUS', category: 'computer' },
  '84:A4:66': { vendor: 'ASUS', category: 'computer' },
  '88:C2:55': { vendor: 'ASUS', category: 'computer' },
  '8C:31:D2': { vendor: 'ASUS', category: 'computer' },
  '90:E6:BA': { vendor: 'ASUS', category: 'computer' },
  '94:10:3E': { vendor: 'ASUS', category: 'computer' },
  '98:32:19': { vendor: 'ASUS', category: 'computer' },
  '9C:5C:8E': { vendor: 'ASUS', category: 'computer' },
  'A0:36:9F': { vendor: 'ASUS', category: 'computer' },
  'A4:34:D9': { vendor: 'ASUS', category: 'computer' },
  'A8:5E:45': { vendor: 'ASUS', category: 'computer' },
  'AC:22:05': { vendor: 'ASUS', category: 'computer' },
  'AC:9E:17': { vendor: 'ASUS', category: 'computer' },
  'B0:6E:BF': { vendor: 'ASUS', category: 'computer' },
  'B4:2E:99': { vendor: 'ASUS', category: 'computer' },
  'B8:EE:65': { vendor: 'ASUS', category: 'computer' },
  'BC:EE:7B': { vendor: 'ASUS', category: 'computer' },
  'C0:94:AD': { vendor: 'ASUS', category: 'computer' },
  'C4:72:30': { vendor: 'ASUS', category: 'computer' },
  'C8:60:00': { vendor: 'ASUS', category: 'computer' },
  'CC:46:D6': { vendor: 'ASUS', category: 'computer' },
  'D0:17:C2': { vendor: 'ASUS', category: 'computer' },
  'D4:5D:64': { vendor: 'ASUS', category: 'computer' },
  'D8:50:E6': { vendor: 'ASUS', category: 'computer' },
  'DC:9F:DB': { vendor: 'ASUS', category: 'computer' },
  'E0:3F:49': { vendor: 'ASUS', category: 'computer' },
  'E4:70:B8': { vendor: 'ASUS', category: 'computer' },
  'E8:94:F6': { vendor: 'ASUS', category: 'computer' },
  'EC:08:6B': { vendor: 'ASUS', category: 'computer' },
  'F0:79:60': { vendor: 'ASUS', category: 'computer' },
  'F4:6D:04': { vendor: 'ASUS', category: 'computer' },
  'F8:32:19': { vendor: 'ASUS', category: 'computer' },
  'FC:C2:DE': { vendor: 'ASUS', category: 'computer' },

  // ── TP-LINK（路由器） ──
  '28:57:BE': { vendor: 'TP-LINK', category: 'router' },
  '14:CF:92': { vendor: 'TP-LINK', category: 'router' },
  '60:A4:B7': { vendor: 'TP-LINK', category: 'router' },
  '90:9A:4A': { vendor: 'TP-LINK', category: 'router' },
  'B0:95:75': { vendor: 'TP-LINK', category: 'router' },
  'CC:34:29': { vendor: 'TP-LINK', category: 'router' },
  'D8:0D:17': { vendor: 'TP-LINK', category: 'router' },
  'F4:EC:38': { vendor: 'TP-LINK', category: 'router' },
  '00:23:CD': { vendor: 'TP-LINK', category: 'router' },
  '10:FE:ED': { vendor: 'TP-LINK', category: 'router' },
  '14:CC:B3': { vendor: 'TP-LINK', category: 'router' },
  '18:A6:F7': { vendor: 'TP-LINK', category: 'router' },
  '1C:3B:F3': { vendor: 'TP-LINK', category: 'router' },
  '20:DC:E6': { vendor: 'TP-LINK', category: 'router' },
  '24:A4:3C': { vendor: 'TP-LINK', category: 'router' },
  '30:B5:C2': { vendor: 'TP-LINK', category: 'router' },
  '34:2C:C4': { vendor: 'TP-LINK', category: 'router' },
  '38:21:87': { vendor: 'TP-LINK', category: 'router' },
  '40:16:7E': { vendor: 'TP-LINK', category: 'router' },
  '44:44:84': { vendor: 'TP-LINK', category: 'router' },
  '48:7D:2F': { vendor: 'TP-LINK', category: 'router' },
  '50:C7:BF': { vendor: 'TP-LINK', category: 'router' },
  '54:C8:0F': { vendor: 'TP-LINK', category: 'router' },
  '58:32:44': { vendor: 'TP-LINK', category: 'router' },
  '5C:E9:1E': { vendor: 'TP-LINK', category: 'router' },
  '60:32:B1': { vendor: 'TP-LINK', category: 'router' },
  '60:E3:27': { vendor: 'TP-LINK', category: 'router' },
  '64:70:02': { vendor: 'TP-LINK', category: 'router' },
  '68:FF:7B': { vendor: 'TP-LINK', category: 'router' },
  '6C:5E:AB': { vendor: 'TP-LINK', category: 'router' },
  '70:4D:7B': { vendor: 'TP-LINK', category: 'router' },
  '74:DA:EA': { vendor: 'TP-LINK', category: 'router' },
  '78:31:2B': { vendor: 'TP-LINK', category: 'router' },
  '78:A1:06': { vendor: 'TP-LINK', category: 'router' },
  '7C:8B:CA': { vendor: 'TP-LINK', category: 'router' },
  '80:2A:A8': { vendor: 'TP-LINK', category: 'router' },
  '84:16:F9': { vendor: 'TP-LINK', category: 'router' },
  '88:25:93': { vendor: 'TP-LINK', category: 'router' },
  '8C:21:0A': { vendor: 'TP-LINK', category: 'router' },
  '90:F6:52': { vendor: 'TP-LINK', category: 'router' },
  '94:D9:B3': { vendor: 'TP-LINK', category: 'router' },
  '98:DA:C4': { vendor: 'TP-LINK', category: 'router' },
  '9C:53:22': { vendor: 'TP-LINK', category: 'router' },
  'A0:04:60': { vendor: 'TP-LINK', category: 'router' },
  'A0:F3:C1': { vendor: 'TP-LINK', category: 'router' },
  'A4:2B:8C': { vendor: 'TP-LINK', category: 'router' },
  'A8:57:02': { vendor: 'TP-LINK', category: 'router' },
  'AC:22:0B': { vendor: 'TP-LINK', category: 'router' },
  'B0:4E:26': { vendor: 'TP-LINK', category: 'router' },
  'B4:B0:24': { vendor: 'TP-LINK', category: 'router' },
  'B8:EE:65': { vendor: 'TP-LINK', category: 'router' },
  'BC:CF:6C': { vendor: 'TP-LINK', category: 'router' },
  'C0:06:C3': { vendor: 'TP-LINK', category: 'router' },
  'C0:25:E9': { vendor: 'TP-LINK', category: 'router' },
  'C0:E4:2D': { vendor: 'TP-LINK', category: 'router' },
  'C4:E9:84': { vendor: 'TP-LINK', category: 'router' },
  'C8:3A:35': { vendor: 'TP-LINK', category: 'router' },
  'CC:08:8D': { vendor: 'TP-LINK', category: 'router' },
  'D0:21:F9': { vendor: 'TP-LINK', category: 'router' },
  'D4:6E:5C': { vendor: 'TP-LINK', category: 'router' },
  'D8:07:B6': { vendor: 'TP-LINK', category: 'router' },
  'DC:A6:32': { vendor: 'TP-LINK', category: 'router' },
  'E0:0C:7F': { vendor: 'TP-LINK', category: 'router' },
  'E0:E5:41': { vendor: 'TP-LINK', category: 'router' },
  'E4:2D:7B': { vendor: 'TP-LINK', category: 'router' },
  'E8:DE:27': { vendor: 'TP-LINK', category: 'router' },
  'EC:08:6B': { vendor: 'TP-LINK', category: 'router' },
  'F0:27:2D': { vendor: 'TP-LINK', category: 'router' },
  'F0:9F:C2': { vendor: 'TP-LINK', category: 'router' },
  'F4:F2:6D': { vendor: 'TP-LINK', category: 'router' },
  'F8:D1:11': { vendor: 'TP-LINK', category: 'router' },
  'FC:D7:33': { vendor: 'TP-LINK', category: 'router' },

  // ── D-Link（路由器） ──
  '00:14:78': { vendor: 'D-Link', category: 'router' },
  '00:1B:11': { vendor: 'D-Link', category: 'router' },
  '00:22:B0': { vendor: 'D-Link', category: 'router' },
  '00:24:01': { vendor: 'D-Link', category: 'router' },
  '00:26:5A': { vendor: 'D-Link', category: 'router' },
  '10:BE:F5': { vendor: 'D-Link', category: 'router' },
  '14:D6:4D': { vendor: 'D-Link', category: 'router' },
  '1C:5F:2B': { vendor: 'D-Link', category: 'router' },
  '1C:BD:B9': { vendor: 'D-Link', category: 'router' },
  '34:60:F9': { vendor: 'D-Link', category: 'router' },
  '90:8D:6C': { vendor: 'D-Link', category: 'router' },
  'A0:63:91': { vendor: 'D-Link', category: 'router' },
  'B0:C5:54': { vendor: 'D-Link', category: 'router' },
  'C0:A0:BB': { vendor: 'D-Link', category: 'router' },
  'C4:E9:84': { vendor: 'D-Link', category: 'router' },
  'E0:46:9A': { vendor: 'D-Link', category: 'router' },
  'F0:7D:68': { vendor: 'D-Link', category: 'router' },
  'FC:75:16': { vendor: 'D-Link', category: 'router' },

  // ── Hikvision 海康威视（摄像头） ──
  '00:18:DD': { vendor: 'Hikvision', category: 'camera' },
  'C4:3C:B0': { vendor: 'Hikvision', category: 'camera' },
  'C0:E7:BF': { vendor: 'Hikvision', category: 'camera' },
  '28:5A:EB': { vendor: 'Hikvision', category: 'camera' },
  '28:63:36': { vendor: 'Hikvision', category: 'camera' },
  '3C:EF:8C': { vendor: 'Hikvision', category: 'camera' },
  '44:19:B6': { vendor: 'Hikvision', category: 'camera' },
  '4C:BD:8F': { vendor: 'Hikvision', category: 'camera' },
  '54:C4:15': { vendor: 'Hikvision', category: 'camera' },
  '58:EF:CF': { vendor: 'Hikvision', category: 'camera' },
  '68:97:E8': { vendor: 'Hikvision', category: 'camera' },
  '70:72:3C': { vendor: 'Hikvision', category: 'camera' },
  '74:DA:EA': { vendor: 'Hikvision', category: 'camera' },
  '78:A7:15': { vendor: 'Hikvision', category: 'camera' },
  '7C:6F:6B': { vendor: 'Hikvision', category: 'camera' },
  '84:A9:3E': { vendor: 'Hikvision', category: 'camera' },
  '8C:E7:48': { vendor: 'Hikvision', category: 'camera' },
  '90:94:E0': { vendor: 'Hikvision', category: 'camera' },
  '94:DB:C9': { vendor: 'Hikvision', category: 'camera' },
  '98:01:A7': { vendor: 'Hikvision', category: 'camera' },
  '9C:14:63': { vendor: 'Hikvision', category: 'camera' },
  'A0:CC:BC': { vendor: 'Hikvision', category: 'camera' },
  'A4:14:37': { vendor: 'Hikvision', category: 'camera' },
  'AC:CC:8E': { vendor: 'Hikvision', category: 'camera' },
  'B0:51:8E': { vendor: 'Hikvision', category: 'camera' },
  'B4:5D:50': { vendor: 'Hikvision', category: 'camera' },
  'B8:6F:0F': { vendor: 'Hikvision', category: 'camera' },
  'BC:AD:AB': { vendor: 'Hikvision', category: 'camera' },
  'C0:56:E3': { vendor: 'Hikvision', category: 'camera' },
  'C4:7C:8D': { vendor: 'Hikvision', category: 'camera' },
  'C8:37:8B': { vendor: 'Hikvision', category: 'camera' },
  'CC:44:63': { vendor: 'Hikvision', category: 'camera' },
  'D0:27:17': { vendor: 'Hikvision', category: 'camera' },
  'D4:1E:35': { vendor: 'Hikvision', category: 'camera' },
  'D8:60:B0': { vendor: 'Hikvision', category: 'camera' },
  'E0:50:8B': { vendor: 'Hikvision', category: 'camera' },
  'E0:CE:44': { vendor: 'Hikvision', category: 'camera' },
  'E4:5D:51': { vendor: 'Hikvision', category: 'camera' },
  'E8:33:0E': { vendor: 'Hikvision', category: 'camera' },
  'EC:08:6B': { vendor: 'Hikvision', category: 'camera' },
  'F0:13:C3': { vendor: 'Hikvision', category: 'camera' },
  'F4:23:11': { vendor: 'Hikvision', category: 'camera' },
  'F8:02:78': { vendor: 'Hikvision', category: 'camera' },
  'FC:48:EF': { vendor: 'Hikvision', category: 'camera' },

  // ── Microsoft / Surface / Xbox ──
  '00:50:F2': { vendor: 'Microsoft', category: 'computer' },
  '30:59:B7': { vendor: 'Microsoft', category: 'computer' },
  '50:1A:C5': { vendor: 'Microsoft', category: 'computer' },
  '60:45:BD': { vendor: 'Microsoft', category: 'computer' },
  'B0:BE:76': { vendor: 'Microsoft', category: 'computer' },
  'C8:3A:6B': { vendor: 'Microsoft', category: 'computer' },
  'D4:25:8B': { vendor: 'Microsoft', category: 'computer' },
  'E8:2A:44': { vendor: 'Microsoft', category: 'computer' },
  'F4:F5:A5': { vendor: 'Microsoft', category: 'computer' },
  '28:18:78': { vendor: 'Microsoft', category: 'computer' },
  '3C:58:C2': { vendor: 'Microsoft', category: 'computer' },
  '54:35:30': { vendor: 'Microsoft', category: 'computer' },
  '7C:1E:52': { vendor: 'Microsoft', category: 'computer' },
  '98:5F:B3': { vendor: 'Microsoft', category: 'computer' },
  'A4:C1:38': { vendor: 'Microsoft', category: 'computer' },
  'B8:31:B5': { vendor: 'Microsoft', category: 'computer' },
  'C8:3E:A7': { vendor: 'Microsoft', category: 'computer' },
  'DC:B4:C4': { vendor: 'Microsoft', category: 'computer' },
  'E8:3A:12': { vendor: 'Microsoft', category: 'computer' },
  'F0:1D:BC': { vendor: 'Microsoft', category: 'computer' },

  // ── Amazon Echo / Kindle ──
  '3C:28:6D': { vendor: 'Amazon', category: 'iot' },
  '68:37:E9': { vendor: 'Amazon', category: 'iot' },
  '74:75:48': { vendor: 'Amazon', category: 'iot' },
  'A4:DA:3C': { vendor: 'Amazon', category: 'iot' },
  '40:B4:CD': { vendor: 'Amazon', category: 'iot' },
  '68:54:FD': { vendor: 'Amazon', category: 'iot' },
  '84:D6:D0': { vendor: 'Amazon', category: 'iot' },
  'A0:02:DC': { vendor: 'Amazon', category: 'iot' },
  'F0:27:2D': { vendor: 'Amazon', category: 'iot' },

  // ── Raspberry Pi ──
  'B8:27:EB': { vendor: 'Raspberry Pi', category: 'iot' },
  'DC:A6:32': { vendor: 'Raspberry Pi', category: 'iot' },
  'E4:5F:01': { vendor: 'Raspberry Pi', category: 'iot' },
  '28:CD:C1': { vendor: 'Raspberry Pi', category: 'iot' },

  // ── NVIDIA Shield ──
  '00:04:4B': { vendor: 'NVIDIA', category: 'iot' },
  '48:B0:2D': { vendor: 'NVIDIA', category: 'iot' },

  // ── Philips Hue ──
  '00:17:88': { vendor: 'Philips Hue', category: 'iot' },

  // ── Intel 网卡 ──
  'C4:47:4E': { vendor: 'Intel', category: 'computer' },
  '3C:97:0E': { vendor: 'Intel', category: 'computer' },
  '48:51:B7': { vendor: 'Intel', category: 'computer' },
  '5C:51:81': { vendor: 'Intel', category: 'computer' },
  '80:86:F2': { vendor: 'Intel', category: 'computer' },
  'A4:4C:C8': { vendor: 'Intel', category: 'computer' },
  'B4:69:46': { vendor: 'Intel', category: 'computer' },
  'CC:D2:81': { vendor: 'Intel', category: 'computer' },

  // ── Realtek 网卡 ──
  '00:E0:4C': { vendor: 'Realtek', category: 'computer' },
  '00:1B:21': { vendor: 'Realtek', category: 'computer' },

  // ── VMware / VirtualBox / Hyper-V / QEMU ──
  '00:50:56': { vendor: 'VMware', category: 'virtual' },
  '00:0C:29': { vendor: 'VMware', category: 'virtual' },
  '08:00:27': { vendor: 'VirtualBox', category: 'virtual' },
  '0A:00:27': { vendor: 'VirtualBox', category: 'virtual' },
  '1E:C5:55': { vendor: 'VirtualBox', category: 'virtual' },
  '00:1C:42': { vendor: 'Parallels', category: 'virtual' },
  '00:15:5D': { vendor: 'Hyper-V', category: 'virtual' },
  '52:54:00': { vendor: 'QEMU/KVM', category: 'virtual' },

  // ── Netgear（路由器） ──
  '00:14:6C': { vendor: 'Netgear', category: 'router' },
  '00:1F:33': { vendor: 'Netgear', category: 'router' },
  '00:24:B2': { vendor: 'Netgear', category: 'router' },
  '00:26:F2': { vendor: 'Netgear', category: 'router' },
  '20:0C:C8': { vendor: 'Netgear', category: 'router' },
  '20:E5:2A': { vendor: 'Netgear', category: 'router' },
  '28:C6:8E': { vendor: 'Netgear', category: 'router' },
  '2C:B0:5D': { vendor: 'Netgear', category: 'router' },
  '30:46:9A': { vendor: 'Netgear', category: 'router' },
  '3C:37:86': { vendor: 'Netgear', category: 'router' },
  '40:4A:03': { vendor: 'Netgear', category: 'router' },
  '44:94:FC': { vendor: 'Netgear', category: 'router' },
  '4C:60:DE': { vendor: 'Netgear', category: 'router' },
  '50:4A:6F': { vendor: 'Netgear', category: 'router' },
  '58:EF:68': { vendor: 'Netgear', category: 'router' },
  '5C:3A:45': { vendor: 'Netgear', category: 'router' },
  '60:38:E0': { vendor: 'Netgear', category: 'router' },
  '6C:B0:CE': { vendor: 'Netgear', category: 'router' },
  '74:AC:B9': { vendor: 'Netgear', category: 'router' },
  '84:1B:5E': { vendor: 'Netgear', category: 'router' },
  '8C:3B:AD': { vendor: 'Netgear', category: 'router' },
  '9C:3D:CF': { vendor: 'Netgear', category: 'router' },
  'A0:04:60': { vendor: 'Netgear', category: 'router' },
  'A0:21:B7': { vendor: 'Netgear', category: 'router' },
  'A4:2B:8C': { vendor: 'Netgear', category: 'router' },
  'B0:7F:B9': { vendor: 'Netgear', category: 'router' },
  'B0:B9:8A': { vendor: 'Netgear', category: 'router' },
  'C0:3F:0E': { vendor: 'Netgear', category: 'router' },
  'C4:04:15': { vendor: 'Netgear', category: 'router' },
  'C8:FF:28': { vendor: 'Netgear', category: 'router' },
  'CC:40:D0': { vendor: 'Netgear', category: 'router' },
  'D0:21:F9': { vendor: 'Netgear', category: 'router' },
  'D4:6E:5C': { vendor: 'Netgear', category: 'router' },
  'E0:46:9A': { vendor: 'Netgear', category: 'router' },
  'E0:91:F5': { vendor: 'Netgear', category: 'router' },
  'E4:F0:04': { vendor: 'Netgear', category: 'router' },
  'E8:FC:AF': { vendor: 'Netgear', category: 'router' },
  'F0:01:0C': { vendor: 'Netgear', category: 'router' },
  'F0:9F:C2': { vendor: 'Netgear', category: 'router' },
  'F4:6D:E2': { vendor: 'Netgear', category: 'router' },
  'F8:73:94': { vendor: 'Netgear', category: 'router' },
  'F8:B1:56': { vendor: 'Netgear', category: 'router' },
  'FC:FB:FB': { vendor: 'Netgear', category: 'router' },

  // ── Apple（扩展） ──
  '30:35:AD': { vendor: 'Apple', category: 'computer' },
  '34:36:3B': { vendor: 'Apple', category: 'computer' },
  '38:0A:94': { vendor: 'Apple', category: 'computer' },
  '3C:15:C2': { vendor: 'Apple', category: 'computer' },
  '40:30:04': { vendor: 'Apple', category: 'computer' },
  '44:07:0B': { vendor: 'Apple', category: 'computer' },
  '48:D7:05': { vendor: 'Apple', category: 'computer' },
  '4C:32:75': { vendor: 'Apple', category: 'computer' },
  '50:DE:06': { vendor: 'Apple', category: 'computer' },
  '54:26:96': { vendor: 'Apple', category: 'computer' },
  '58:55:CA': { vendor: 'Apple', category: 'computer' },
  '5C:F7:E6': { vendor: 'Apple', category: 'computer' },
  '60:03:08': { vendor: 'Apple', category: 'computer' },
  '64:5A:04': { vendor: 'Apple', category: 'computer' },
  '68:9C:70': { vendor: 'Apple', category: 'computer' },
  '6C:4D:73': { vendor: 'Apple', category: 'computer' },
  '70:11:24': { vendor: 'Apple', category: 'computer' },
  '74:E2:F5': { vendor: 'Apple', category: 'computer' },
  '78:31:C1': { vendor: 'Apple', category: 'computer' },
  '78:7B:8A': { vendor: 'Apple', category: 'phone' },
  '7C:1D:D9': { vendor: 'Apple', category: 'computer' },
  '80:CE:62': { vendor: 'Apple', category: 'computer' },
  '84:B1:53': { vendor: 'Apple', category: 'computer' },
  '88:19:8F': { vendor: 'Apple', category: 'computer' },
  '88:E9:FE': { vendor: 'Apple', category: 'computer' },
  '8C:85:90': { vendor: 'Apple', category: 'computer' },
  '94:65:9C': { vendor: 'Apple', category: 'computer' },
  '98:01:A7': { vendor: 'Apple', category: 'computer' },
  '9C:20:7B': { vendor: 'Apple', category: 'phone' },
  '9C:F3:87': { vendor: 'Apple', category: 'computer' },
  'A4:5E:60': { vendor: 'Apple', category: 'computer' },
  'A4:D1:8C': { vendor: 'Apple', category: 'computer' },
  'A8:5C:2C': { vendor: 'Apple', category: 'phone' },
  'A8:86:DD': { vendor: 'Apple', category: 'computer' },
  'AC:BC:32': { vendor: 'Apple', category: 'computer' },
  'B0:34:95': { vendor: 'Apple', category: 'computer' },
  'B4:4B:D0': { vendor: 'Apple', category: 'computer' },
  'B8:C7:5D': { vendor: 'Apple', category: 'computer' },
  'BC:52:B7': { vendor: 'Apple', category: 'computer' },
  'C0:B6:58': { vendor: 'Apple', category: 'computer' },
  'C4:2C:03': { vendor: 'Apple', category: 'computer' },
  'C8:69:CD': { vendor: 'Apple', category: 'computer' },
  'CC:46:D6': { vendor: 'Apple', category: 'computer' },
  'D0:03:4B': { vendor: 'Apple', category: 'computer' },
  'D4:61:9D': { vendor: 'Apple', category: 'computer' },
  'D8:BB:C1': { vendor: 'Apple', category: 'computer' },
  'DC:A4:CA': { vendor: 'Apple', category: 'computer' },
  'E0:C9:7A': { vendor: 'Apple', category: 'computer' },
  'E4:25:E7': { vendor: 'Apple', category: 'computer' },
  'E8:8D:56': { vendor: 'Apple', category: 'computer' },
  'EC:FA:AA': { vendor: 'Apple', category: 'computer' },
  'F0:18:98': { vendor: 'Apple', category: 'computer' },
  'F4:34:F0': { vendor: 'Apple', category: 'phone' },
  'F8:FF:C2': { vendor: 'Apple', category: 'computer' },
  'FC:E9:98': { vendor: 'Apple', category: 'computer' },
};

/**
 * 路由器 / 网关 OUI 前缀（用于识别网关设备）
 */
Scanner.ROUTER_OUIS = new Set([
  '00:E0:FC', '28:6C:07', // Huawei 路由器
  '28:57:BE', '14:CF:92', '60:A4:B7', '90:9A:4A', 'B0:95:75',
  'CC:34:29', 'D8:0D:17', 'F4:EC:38', // TP-LINK
  '00:14:78', '00:1B:11', '00:22:B0', '00:24:01', '00:26:5A',
  '10:BE:F5', '14:D6:4D', '1C:5F:2B', '1C:BD:B9', '34:60:F9',
  '90:8D:6C', 'A0:63:91', 'B0:C5:54', 'C0:A0:BB', 'C4:E9:84',
  'E0:46:9A', 'F0:7D:68', 'FC:75:16', // D-Link
  '00:14:6C', '00:1F:33', '00:24:B2', '00:26:F2', '20:0C:C8',
  '20:E5:2A', '28:C6:8E', '2C:B0:5D', '30:46:9A', '3C:37:86',
  '40:4A:03', '44:94:FC', '4C:60:DE', '50:4A:6F', '58:EF:68',
  '5C:3A:45', '60:38:E0', '6C:B0:CE', '74:AC:B9', '84:1B:5E',
  '8C:3B:AD', '9C:3D:CF', 'A0:04:60', 'A0:21:B7', 'A4:2B:8C',
  'B0:7F:B9', 'B0:B9:8A', 'C0:3F:0E', 'C4:04:15', 'C8:FF:28',
  'CC:40:D0', 'D0:21:F9', 'D4:6E:5C', 'E0:91:F5', 'E4:F0:04',
  'E8:FC:AF', 'F0:01:0C', 'F0:9F:C2', 'F4:6D:E2', 'F8:73:94',
  'F8:B1:56', 'FC:FB:FB', // Netgear
  'B0:E3:B5', // Xiaomi 路由器
]);

/**
 * 隐私 MAC 检测：Apple / Android / Windows 随机地址
 */
Scanner.isPrivacyMac = function(mac) {
  if (!mac || mac === '00:00:00:00:00:00') return false;
  const parts = mac.split(':');
  if (parts.length !== 6) return false;
  const first = parseInt(parts[0], 16);
  // Locally administered bit (bit 1) = 1 → 随机/本地管理地址
  if (first & 0x02) return true;
  return false;
};

/**
 * 设备类型分类规则
 */
Scanner.CATEGORY_LABELS = {
  phone: '手机',
  computer: '电脑',
  router: '路由器/网关',
  iot: 'IoT 设备',
  camera: '摄像头',
  virtual: '虚拟网卡',
  unknown: '网络设备'
};

/**
 * 在线 OUI 查询缓存
 */
Scanner._ouiCache = new Map();
Scanner._ouiFetching = new Set();

/**
 * 在线查询 OUI 厂商信息（带缓存）
 * 使用 maclookup.app API
 */
Scanner.lookupOuiOnline = function(mac) {
  const oui = mac.slice(0, 8).toUpperCase().replace(/:/g, '');

  // 已缓存
  if (Scanner._ouiCache.has(oui)) {
    return Promise.resolve(Scanner._ouiCache.get(oui));
  }

  // 正在查询中
  if (Scanner._ouiFetching.has(oui)) {
    return Promise.resolve({ vendor: null, pending: true });
  }

  Scanner._ouiFetching.add(oui);

  return new Promise((resolve) => {
    const req = https.get(`https://maclookup.app/api/v2/macs/${oui}`, {
      timeout: 3000
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        Scanner._ouiFetching.delete(oui);
        try {
          const json = JSON.parse(data);
          if (json.success && json.company) {
            const result = { vendor: json.company, category: 'unknown' };
            Scanner._ouiCache.set(oui, result);
            resolve(result);
          } else {
            const result = { vendor: null, category: 'unknown' };
            Scanner._ouiCache.set(oui, result);
            resolve(result);
          }
        } catch {
          resolve({ vendor: null, category: 'unknown' });
        }
      });
    });

    req.on('error', () => {
      Scanner._ouiFetching.delete(oui);
      resolve({ vendor: null, category: 'unknown' });
    });

    req.on('timeout', () => {
      req.destroy();
      Scanner._ouiFetching.delete(oui);
      resolve({ vendor: null, category: 'unknown' });
    });
  });
};

/**
 * 通过 MAC 地址推断设备类型
 * 返回 { vendor, type, category }
 */
Scanner.inferDeviceType = function(mac, ip, gateway) {
  if (!mac || mac === '00:00:00:00:00:00') {
    return { vendor: null, type: '在线设备', category: 'unknown' };
  }

  const oui = mac.slice(0, 8).toUpperCase();

  // 1. 网关设备检测（通过 IP 判断，不是 MAC）
  if (gateway && ip === gateway) {
    const entry = Scanner.OUI_DB[oui];
    return {
      vendor: entry ? entry.vendor : null,
      type: entry ? `${entry.vendor} 路由器/网关` : '路由器/网关',
      category: 'router'
    };
  }

  // 2. 路由器厂商 OUI 检测
  if (Scanner.ROUTER_OUIS.has(oui)) {
    const entry = Scanner.OUI_DB[oui];
    return {
      vendor: entry ? entry.vendor : null,
      type: entry ? `${entry.vendor} 路由器/网关` : '路由器/网关',
      category: 'router'
    };
  }

  // 3. OUI 数据库查询
  const entry = Scanner.OUI_DB[oui];
  if (entry) {
    const label = Scanner.CATEGORY_LABELS[entry.category] || entry.category;
    return {
      vendor: entry.vendor,
      type: `${entry.vendor} ${label}`,
      category: entry.category
    };
  }

  // 4. 隐私地址检测
  if (Scanner.isPrivacyMac(mac)) {
    return { vendor: null, type: '随机 MAC / 隐私地址设备', category: 'unknown' };
  }

  return { vendor: null, type: '网络设备', category: 'unknown' };
};

module.exports = Scanner;
