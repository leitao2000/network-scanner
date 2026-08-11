

# 网络扫描器 (Network Scanner)

一个功能强大的跨平台网络扫描工具，基于 Electron 构建，支持智能设备发现、端口扫描、网络拓扑可视化等特性。

## 功能特性

### 🔍 核心扫描功能
- **IP 扫描**：快速扫描本地网络，发现在线设备
- **端口扫描**：支持标准端口及自定义端口范围检测
- **Traceroute**：追踪数据包路由路径
- **DNS 诊断**：正向/反向 DNS 解析
- **UDP 扫描**：支持常见 UDP 服务检测
- **操作系统识别**：智能识别设备操作系统类型

### 📡 网络信息展示
- 自动获取本机网络信息（IP、网关、子网掩码等）
- 实时显示在线设备数量统计
- 支持多网卡适配器切换
- 历史扫描记录保存与回溯

### 🖥️ 设备详细信息
- 设备 IP、主机名、MAC 地址信息
- 开放端口及服务识别
- Ping 测试与连通性检测
- Wake-on-LAN 远程唤醒功能

### 🌐 可视化界面
- **网络拓扑图**：直观展示设备连接关系
- **设备列表**：支持排序、筛选、分组查看
- **统计分析图表**：厂商分布、端口分布、趋势分析
- **深色/浅色主题切换**

### 🤖 AI 智能分析
- 设备类型智能识别
- 安全风险评估
- 配置建议与优化方案
- 支持主流 AI 服务集成（OpenAI、Claude 等）

### 📤 报告导出
- HTML 格式报告
- JSON 格式数据导出
- CSV 表格文件

## 技术架构

- **前端框架**：原生 HTML + CSS + JavaScript
- **桌面框架**：Electron
- **后端核心**：Node.js + 原生网络模块
- **依赖管理**：npm

## 系统要求

- **操作系统**：
  - Windows 10/11
  - macOS 10.15+
  - Linux (Ubuntu 20.04+ / Fedora 35+)
  
- **运行环境**：
  - Node.js 18+
  - npm 9+

## 安装指南

### 方式一：从源码编译

```bash
# 克隆项目
git clone https://gitee.com/leitao2000/network-scanner.git
cd network-scanner

# 安装依赖
npm install

# 启动开发模式
npm run dev

# 构建生产版本
npm run build
```

### 方式二：使用预编译版本

前往 [Gitee Releases](https://gitee.com/leitao2000/network-scanner/releases) 下载对应平台的安装包。

## 使用说明

### 快速开始

1. 启动应用后，主界面将自动检测并显示本机网络信息
2. 点击「开始扫描」按钮执行网络扫描
3. 扫描完成后，可在设备列表中查看所有在线设备
4. 点击设备可查看详细信息，执行 Ping、端口扫描等操作

### AI 功能配置

1. 点击右上角「AI 配置」按钮
2. 选择 AI 服务提供商（支持 OpenAI、Claude 等）
3. 填写 API Key 和模型名称
4. 保存配置后即可使用 AI 分析功能

### 扫描选项

- **扫描模式**：快速扫描 / 完整扫描
- **超时设置**：自定义 Ping 超时时间
- **端口范围**：自定义扫描端口列表
- **并行数量**：控制并发扫描线程数

## 项目结构

```
network-scanner/
├── main.js              # Electron 主进程入口
├── preload.js           # 预加载脚本
├── scanner.js           # 核心扫描引擎
├── test-scanner.js      # 测试文件
├── scan-online-ips.js   # 在线 IP 扫描模块
├── colors_and_type.css  # 样式文件
├── pages/
│   ├── app.js          # 前端逻辑
│   └── index.html      # 主界面
├── assets/
│   └── lucide.min.js   # 图标库
└── package.json         # 项目配置
```

## API 参考

### Scanner 类

```javascript
const Scanner = require('./scanner.js');

// 获取本机网络信息
const localInfo = await Scanner.getLocalInfo();

// 扫描网络
const results = await scanner.scanNetwork({
    timeout: 2000,
    ports: [21, 22, 80, 443, 8080]
});

// 端口扫描
const openPorts = await scanner.scanPorts('192.168.1.1', [21, 22, 80]);

// Traceroute
const route = await Scanner.traceroute('8.8.8.8');
```

## 常见问题

**Q: 扫描速度慢怎么办？**
A: 尝试降低超时时间或减少扫描端口数量，同时确保系统已授予必要的网络权限。

**Q: Linux 下扫描权限不足？**
A: 执行 `sudo setcap 'cap_net_raw+ep' $(which node)` 赋予 Node.js 原始套接字权限。

**Q: AI 功能无法使用？**
A: 请检查 AI 配置是否正确，并确认网络可以访问对应的 API 服务。

## 相关命令

| 命令 | 说明 |
|------|------|
| `npm install` | 安装项目依赖 |
| `npm run dev` | 启动开发服务器 |
| `npm run build` | 构建生产版本 |
| `npm test` | 运行测试 |

## 贡献指南

欢迎提交 Issue 或 Pull Request 贡献代码。

1. Fork 本项目
2. 创建功能分支：`git checkout -b feature/new-feature`
3. 提交更改：`git commit -am 'Add new feature'`
4. 推送到远程：`git push origin feature/new-feature`
5. 提交 Pull Request

## 开源协议

本项目基于 MIT 协议开源。

## 联系方式

- **项目地址**：https://gitee.com/leitao2000/network-scanner
- **问题反馈**：https://gitee.com/leitao2000/network-scanner/issues