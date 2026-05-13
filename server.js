import { Server } from 'bittorrent-tracker';
import http from 'http';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import process from 'process';

// AI Studio binds external traffic ONLY to port 3000
const PORT = 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// 1. Initialize Express for the Web/API layer
const app = express();

// A. Enable Trust Proxy (Crucial for Cloud Run/Render/Heroku Peer IP detection)
app.set('trust proxy', true);

// B. Rate Limiting (Security against DDoS/Spam)
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP, please try again later." }
});

// Protect only the announce and scrape endpoints
app.use(['/announce', '/scrape'], limiter);

// C. Health Check and Status Routes
app.get(['/', '/health'], (req, res) => {
  res.json({
    status: 'ok',
    service: 'KaspStore Multi-Client P2P Tracker',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    protocol: 'WebTorrent + HTTP',
    auth_enabled: !!process.env.TRACKER_API_KEY
  });
});

// 2. Create the Shared HTTP/WS Server
const httpServer = http.createServer(app);

// 3. Initialize the Tracker
const tracker = new Server({
  udp: false,         // UDP is blocked on most PaaS providers
  http: true,        // Standard BitTorrent HTTP tracker
  ws: true,          // WebTorrent WebSocket tracker
  stats: true,       // /stats endpoint enabled
  trustProxy: true,
  server: httpServer, // Share the same port as Express
  
  // ─── HARDENED AUTHENTICATION FILTER (STRICT MODE) ───
  filter: (infoHash, params, cb) => {
    const requiredKey = process.env.TRACKER_API_KEY;
    
    // 1. Strict Privacy
    if (!requiredKey) {
      return cb(new Error('KaspStore Security: TRACKER_API_KEY environment variable is NOT SET. Mode: Locked.'));
    }

    // 2. Auth Check: Verify key from query (?api_key=...)
    const clientKey = params.api_key || params.token;

    if (clientKey === requiredKey) {
      // 3. InfoHash Validation: Prevent "Junk Hash" spam (optional but good for scale)
      if (!infoHash || infoHash.length !== 40) {
        return cb(new Error('Invalid InfoHash format.'));
      }
      cb(null); 
    } else {
      // Debug log for unauthorized attempts (Red Team Monitoring)
      console.warn(`[AUTH_FAIL] IP: ${params.ip || 'Unknown'} | Hash: ${infoHash}`);
      cb(new Error('Unauthorized KaspStore Access.'));
    }
  }
});

// 4. Advanced Stability & Debugging
const statsInterval = setInterval(() => {
  const mem = process.memoryUsage();
  if (mem.rss > 1024 * 1024 * 800) { // 800MB Warning
    console.error('🚨 HIGH MEMORY DETECTED: Tracker approaching limit. Scaling suggested.');
  }
}, 30000).unref();

// 4. Performance & Reliability Tuning
// Monitoring events to catch issues before they crash the process
tracker.on('error', (err) => {
  console.error(`❌ Tracker Runtime Error: ${err.message}`);
});

tracker.on('warning', (err) => {
  if (!err.message.includes('ignoring invalid')) {
    console.warn(`⚠️ Tracker Warning: ${err.message}`);
  }
});

// Swarm Lifecycle Logging (Minimal for performance)
tracker.on('start', (addr) => {
  if (!IS_PROD) console.log(`🟢 Swarm Node Connected: ${addr}`);
});

// 5. Start the Hardened Server
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`
===================================================
🚀 KASPSTORE P2P TRACKER - HARDENED 🚀
===================================================
📡 WebTorrent (WS)  : wss://<your-domain>/announce
🌐 HTTP Tracker      : https://<your-domain>/announce
📊 Metrics Engine    : https://<your-domain>/stats
🏥 Health Monitor    : https://<your-domain>/health

Config:
- Rate Limiting      : ENABLED (100req/min)
- Proxy Transparency : ENABLED
- Mode               : ${process.env.TRACKER_API_KEY ? 'PRIVATE (KaspStore Auth)' : 'OPEN (Public)'}
- Port               : ${PORT}
===================================================
  `);
});

// 6. Graceful Shutdown (No Point of Failure logic)
// Ensures any pending swarm writes or connections are closed properly
const gracefulShutdown = (signal) => {
  console.log(`\n📴 Received ${signal}. Shutting down tracker...`);
  
  // Close tracker first
  tracker.close(() => {
    console.log('✅ Swarms cleared and tracker stopped.');
    // Then close the server
    httpServer.close(() => {
      console.log('✅ HTTP server closed. Goodbye.');
      process.exit(0);
    });
  });

  // Force shutdown if it takes too long
  setTimeout(() => {
    console.error('⚠️ Could not close connections in time, forceful shutdown.');
    process.exit(1);
  }, 10000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Catch unhandled errors to prevent crashing
process.on('uncaughtException', (err) => {
  console.error('💥 FATAL ERROR:', err);
  // Optional: Send to logging service here
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});
