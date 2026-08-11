# Network Scanner

A powerful cross-platform network scanning tool built on Electron, supporting features such as intelligent device discovery, port scanning, network topology visualization, and more.

## Features

### 🔍 Core Scanning Functions
- **IP Scan**: Quickly scan the local network to discover online devices.
- **Port Scan**: Supports detection of standard ports and custom port ranges.
- **Traceroute**: Trace packet routing paths.
- **DNS Diagnostics**: Forward/Reverse DNS resolution.
- **UDP Scan**: Supports detection of common UDP services.
- **Operating System Detection**: Intelligently identify device operating system types.

### 📡 Network Information Display
- Automatically retrieve local network information (IP, gateway, subnet mask, etc.).
- Display real-time statistics on the number of online devices.
- Support switching between multiple network adapters.
- Save and review historical scan records.

### 🖥️ Detailed Device Information
- Device IP, hostname, and MAC address information.
- Open ports and service identification.
- Ping tests and connectivity checks.
- Wake-on-LAN remote wake-up function.

### 🌐 Visualization Interface
- **Network Topology Map**: Intuitively display device connection relationships.
- **Device List**: Support sorting, filtering, and grouped viewing.
- **Statistical Analysis Charts**: Vendor distribution, port distribution, trend analysis.
- **Dark/Light Theme Switching**.

### 🤖 AI Intelligent Analysis
- Intelligent device type identification.
- Security risk assessment.
- Configuration suggestions and optimization plans.
- Support for integration with mainstream AI services (OpenAI, Claude, etc.).

### 📤 Report Export
- HTML format reports.
- JSON format data export.
- CSV spreadsheet files.

## Technical Architecture

- **Frontend Framework**: Native HTML + CSS + JavaScript
- **Desktop Framework**: Electron
- **Backend Core**: Node.js + Native Network Modules
- **Dependency Management**: npm

## System Requirements

- **Operating Systems**:
  - Windows 10/11
  - macOS 10.15+
  - Linux (Ubuntu 20.04+ / Fedora 35+)

- **Runtime Environment**:
  - Node.js 18+
  - npm 9+

## Installation Guide

### Method 1: Compile from Source

```bash
# Clone the project
git clone https://gitee.com/leitao2000/network-scanner.git
cd network-scanner

# Install dependencies
npm install

# Start development mode
npm run dev

# Build production version
npm run build
```

### Method 2: Use Pre-compiled Version

Go to [Gitee Releases](https://gitee.com/leitao2000/network-scanner/releases) to download the installer for your platform.

## Usage Instructions

### Quick Start

1. After launching the application, the main interface will automatically detect and display local network information.
2. Click the "Start Scan" button to perform a network scan.
3. Once the scan is complete, view all online devices in the device list.
4. Click on a device to view detailed information and perform operations such as Ping and port scanning.

### AI Function Configuration

1. Click the "AI Configuration" button in the top right corner.
2. Select an AI service provider (supports OpenAI, Claude, etc.).
3. Enter the API Key and model name.
4. Save the configuration to start using AI analysis features.

### Scan Options

- **Scan Mode**: Fast Scan / Full Scan
- **Timeout Settings**: Custom Ping timeout duration
- **Port Range**: Custom scan port list
- **Concurrency**: Control the number of concurrent scan threads

## Project Structure

```
network-scanner/
├── main.js              # Electron main process entry
├── preload.js           # Preload script
├── scanner.js           # Core scanning engine
├── test-scanner.js      # Test file
├── scan-online-ips.js   # Online IP scan module
├── colors_and_type.css  # Style file
├── pages/
│   ├── app.js          # Frontend logic
│   └── index.html      # Main interface
├── assets/
│   └── lucide.min.js   # Icon library
└── package.json         # Project configuration
```

## API Reference

### Scanner Class

```javascript
const Scanner = require('./scanner.js');

// Get local network information
const localInfo = await Scanner.getLocalInfo();

// Scan network
const results = await scanner.scanNetwork({
    timeout: 2000,
    ports: [21, 22, 80, 443, 8080]
});

// Port scan
const openPorts = await scanner.scanPorts('192.168.1.1', [21, 22, 80]);

// Traceroute
const route = await Scanner.traceroute('8.8.8.8');
```

## Frequently Asked Questions

**Q: What can I do if the scan speed is slow?**
A: Try lowering the timeout duration or reducing the number of scanned ports, and ensure the system has granted necessary network permissions.

**Q: Insufficient scan permissions under Linux?**
A: Execute `sudo setcap 'cap_net_raw+ep' $(which node)` to grant Node.js raw socket permissions.

**Q: AI function is unusable?**
A: Please check if the AI configuration is correct and confirm that the network can access the corresponding API service.

## Related Commands

| Command | Description |
|------|------|
| `npm install` | Install project dependencies |
| `npm run dev` | Start development server |
| `npm run build` | Build production version |
| `npm test` | Run tests |

## Contribution Guide

Welcome to submit Issues or Pull Requests to contribute code.

1. Fork this project
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to remote: `git push origin feature/new-feature`
5. Submit Pull Request

## Open Source License

This project is open sourced under the MIT License.

## Contact Information

- **Project Address**: https://gitee.com/leitao2000/network-scanner
- **Issue Feedback**: https://gitee.com/leitao2000/network-scanner/issues