const Scanner = require('./scanner');

async function main() {
  const localInfo = await Scanner.getLocalInfo();
  const adapter = localInfo.activeAdapter;

  if (!adapter) {
    console.error('未找到活动网卡');
    process.exit(1);
  }

  const cidr = adapter.cidr;
  console.error(`网卡: ${adapter.name}`);
  console.error(`扫描目标: ${cidr}`);
  console.error('');

  const scanner = new Scanner();
  const onlineIps = [];

  scanner.on('device', (device) => {
    if (device.status === '在线') {
      onlineIps.push(device.ip);
    }
  });

  scanner.on('progress', (data) => {
    if (data.phase === 'scanning') {
      process.stderr.write(`\r进度: ${data.scanned}/${data.total}  已发现在线: ${onlineIps.length}`);
    }
  });

  const result = await scanner.scanNetwork({ cidr, concurrency: 20 });

  process.stderr.write('\r');
  console.error(`扫描完成：${result.totalHosts} 主机中 ${result.devices.length} 台在线`);
  console.error('');

  for (const ip of onlineIps) {
    console.log(ip);
  }
}

main().catch(err => {
  console.error('扫描出错:', err.message);
  process.exit(1);
});
