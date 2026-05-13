# 🚀 KaspStore P2P Tracker

A high-performance, multi-protocol BitTorrent and WebTorrent tracker designed for the **KaspStore Decentralized Ecosystem**. This server facilitates peer-to-peer data exchange across Web, Mobile, and Desktop clients.

## ✨ Features

-   **Dual Protocol Support**: Handles both standard BitTorrent (HTTP) and WebTorrent (WebSockets).
-   **Hardened Security**: Integrated rate-limiting, API Key authentication, and a **Virtual Patch for CVE-2024-29415**. We use `ipaddr.js` to block sophisticated SSRF attacks (like obfuscated decimal/octal IPs) that standard `ip` packages fail to catch.
-   **Trillion-Scale Ready**: Optimized for high-throughput P2P signaling with automatic memory monitoring and graceful shutdown to prevent point-of-failure.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/kaspstore-tracker.git
cd kaspstore-tracker
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Generate an API Key
Run this command in your terminal to generate a secure secret key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 4. Configure Environment Variables
Create a `.env` file or set these in your deployment dashboard:
```env
PORT=3000
TRACKER_API_KEY=your_generated_key_here
NODE_ENV=production
```

---

## 🚀 Deployment

### Important: Node.js Runtime Required
This is a **Server-Side Application**. It **cannot** be hosted on GitHub Pages, 4Everland Static, or Vercel Frontend. You must use a platform that supports Node.js processes.

**Recommended Platforms:**
-   **Render.com** (Web Service)
-   **Railway.app**
-   **Fly.io**
-   **Google Cloud Run**

### GitHub Privacy: Public vs. Private
-   **Private Repo**: Use if you want to keep your specific implementation or custom logic hidden.
-   **Public Repo**: Safe to use even with security, **provided you never commit your `.env` file**. The logic is public, but the "lock" (API Key) is only in your deployment settings.

---

## 📡 Usage (Announce URLs)

To use this tracker in your torrents or P2P clients, use the following URLs.

### For WebTorrent (Browser-based):
`wss://your-domain.com/announce?api_key=your_key`

### For Standard BitTorrent (Desktop/Mobile):
`https://your-domain.com/announce?api_key=your_key`

---

## 📊 Endpoints

-   `/health`: Check if the server is alive.
-   `/stats`: View current swarms, seeds, and leeches.
-   `/announce`: The P2P heartbeat endpoint.

---

## 📜 License
Internal use for KaspStore.
