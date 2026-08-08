const Scanner = require('./scanner');

async function runTests() {
  console.log('=== 本地网络扫描器测试 ===\n');

  // 1. 本机网络信息
  console.log('1. 本机网络信息');
  const localInfo = await Scanner.getLocalInfo();
  console.log(JSON.stringify(localInfo, null, 2));

  const activeAdapter = localInfo.activeAdapter;
  if (!activeAdapter) {
    console.error('未找到活动网卡，测试终止');
    process.exit(1);
  }
  console.log(`\n活动网卡: ${activeAdapter.name} (${activeAdapter.cidr})`);

  // 2. ARP 表
  console.log('\n2. ARP 缓存表');
  const arp = await Scanner.getArpTable();
  if (arp.error) {
    console.log(`获取 ARP 表失败: ${arp.error}`);
  } else {
    console.log(`ARP 条目数: ${arp.entries.length}`);
    arp.entries.slice(0, 5).forEach(e => console.log(`  ${e.ip} -> ${e.mac} (${e.type})`));
  }

  // 3. Ping 测试
  console.log('\n3. Ping 测试');
  const scanner = new Scanner();
  const pingTargets = ['127.0.0.1', activeAdapter.address, activeAdapter.network.replace(/\.0$/, '.1')];
  for (const target of pingTargets) {
    const result = await scanner.ping(target, 1500);
    console.log(`  ${target}: ${result.alive ? '在线' : '离线'} ${result.latency != null ? result.latency + 'ms' : ''}`);
  }

  // 4. 主机名解析
  console.log('\n4. 主机名解析');
  for (const target of ['127.0.0.1', activeAdapter.address]) {
    const hostname = await Scanner.resolveHostname(target).catch(() => null);
    console.log(`  ${target}: ${hostname || '无结果'}`);
  }

  // 5. 小范围网络扫描（/30，仅 2 个主机，快速验证）
  console.log('\n5. 小范围网络扫描（/30）');
  const testCidr = `${activeAdapter.network.replace(/\.0$/, '')}.0/30`;
  scanner.on('progress', (p) => {
    console.log(`  进度: ${p.phase} ${p.scanned}/${p.total} 发现 ${p.found} 耗时 ${p.elapsed}ms`);
  });
  scanner.on('device', (d) => {
    console.log(`  发现设备: ${d.ip} ${d.mac || ''} ${d.hostname || ''} [${d.type}]`);
  });
  scanner.on('deviceUpdate', (d) => {
    console.log(`  设备更新: ${d.ip} ${d.mac || ''} [${d.type}]`);
  });
  const scanResult = await scanner.scanNetwork({ cidr: testCidr, concurrency: 10 });
  console.log(`  扫描完成: ${scanResult.totalHosts} 主机, ${scanResult.devices.length} 在线, 耗时 ${scanResult.elapsed}ms`);

  // 6. 端口扫描（本机常用端口）
  console.log('\n6. 本机端口扫描');
  const openPorts = await scanner.scanPorts('127.0.0.1', [80, 443, 3306, 3389, 8080]);
  console.log(`  开放端口: ${openPorts.length ? openPorts.join(', ') : '无'}`);

  console.log('\n=== 测试完成 ===');
}

runTests().catch(err => {
  console.error('测试出错:', err);
  process.exit(1);
});
