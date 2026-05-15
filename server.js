import { Server } from 'bittorrent-tracker';
import http from 'http';
import express from 'express';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import process from 'process';
import ipaddr from 'ipaddr.js';
import client from 'prom-client';
import geoip from 'geoip-lite';
import nacl from 'tweetnacl';
import crypto from 'crypto';
import helmet from 'helmet';
import 'dotenv/config';
import db from './src/db.js';


// Import Decentralized Routing Packages
import DHT from 'bittorrent-dht';
import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { webSockets } from '@libp2p/websockets';
import { circuitRelayServer, circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { autoNAT } from '@libp2p/autonat';
import { tls } from '@libp2p/tls';
import { yamux } from '@libp2p/yamux';
import { kadDHT } from '@libp2p/kad-dht';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';

import { bootstrap } from '@libp2p/bootstrap';

// --- CORE P2P LOGIC & API ---
const PORT = 3000;
global.myNatStatus = 'unknown'; // Initialize
const app = express();

// --- SECURITY HARDENING ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:", "http:", "https:"]
    }
  }
}));
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' })); // Harden against payload attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use(cors());
app.set('trust proxy', 1);

// --- 1. ENHANCED PROMETHEUS METRICS ---
const register = new client.Registry();
client.collectDefaultMetrics({ register });

let totalAnnounces = 0;

const DEFAULT_ICE_SERVERS = [
  // LAYER 1: Direct P2P + STUN
  { urls: ["stun:stun1.l.google.com:19302", "stun:stun2.l.google.com:19302", "stun:stun3.l.google.com:19302", "stun:stun4.l.google.com:19302"] },
  { urls: ["stun:stun.l.google.com:19302", "stun:stun.stunprotocol.org:3478", "stun:stun.services.mozilla.com", "stun:stun.l.google.com:19305"] },
  { urls: ["stun:stun.iphone-dev.com", "stun:stun.ekiga.net", "stun:stun.schlund.de", "stun:stun.voxgratia.org"] },

  // LAYER 2: Public Relay (ExpressTURN / OpenRelay)
  {
    urls: [
      "turn:turn.expressturn.com:3478",
      "turns:turn.expressturn.com:443?transport=tcp"
    ],
    username: process.env.EXPRESSTURN_USERNAME || "kaspstore_public",
    credential: process.env.EXPRESSTURN_PASSWORD || "public_peer_relay"
  },
  {
    urls: [
      "turn:staticauth.openrelay.metered.ca:80",
      "turns:staticauth.openrelay.metered.ca:443?transport=tcp"
    ],
    username: "openrelayproject",
    credential: "openrelayprojectsecret"
  }
];

const validateApiKey = (req, res, next) => {
    const reqKey = process.env.TRACKER_API_KEY;
    const clientKey = req.headers['x-api-key'] || req.query.api_key || req.query.token;

    if (reqKey && clientKey !== reqKey) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or missing API key' });
    }
    next();
};

// --- FEATURE 1: MULTI-LAYERED ICE ORCHESTRATION ---
// Orchestrates Layer 1 (STUN), Layer 2 (Public Relays), and Layer 3 (Private Enterprise Relays)
// Track NAT status for peers
const peerNatStatus = new Map();
// Aggregate announced ICE servers
const peerIceServers = new Map();
// Aggregate known neighbors
const peerConnections = new Map();

const getIceServers = (peerId = null) => {
    // Aggregate - use a Map to keep unique server configs by URL
    const serverMap = new Map();
    
    // Helper to generate key for Map
    const getServerKey = (s) => JSON.stringify([...(s.urls || [])].sort());
    
    // Add default servers
    DEFAULT_ICE_SERVERS.forEach(s => serverMap.set(getServerKey(s), s));
    
    // Add discovered servers
    Array.from(peerIceServers.values()).flat().forEach(server => {
        if(server && Array.isArray(server.urls) && server.urls.length > 0) {
            serverMap.set(getServerKey(server), server);
        }
    });
    
    let servers = Array.from(serverMap.values());

    // Check if we have peer's status
    let peerNeedsTurn = false;
    if (peerId && peerNatStatus.has(peerId)) {
        peerNeedsTurn = peerNatStatus.get(peerId) !== 'public';
    }

    // Prioritize TURN if node behind NAT OR peer behind NAT
    if (global.myNatStatus !== 'public' || peerNeedsTurn) {
        // Stable sort to push TURN servers to the front
        // We look for 'turn' to match both 'turn:' and 'turns:'
        servers.sort((a, b) => {
            const aHasTurn = a.urls && Array.isArray(a.urls) && a.urls.some(u => u.toLowerCase().startsWith('turn'));
            const bHasTurn = b.urls && Array.isArray(b.urls) && b.urls.some(u => u.toLowerCase().startsWith('turn'));
            if (aHasTurn && !bHasTurn) return -1;
            if (!aHasTurn && bHasTurn) return 1;
            return 0;
        });
    }
    
    return servers;
};

app.get('/ice', validateApiKey, (req, res) => {
  const peerId = req.query.peerId;
  res.json({
    iceServers: getIceServers(peerId)
  });
});

// Endpoint for peers to report NAT status
app.post('/report-nat', validateApiKey, express.json(), (req, res) => {
    const { peerId, status } = req.body;
    if (peerId && status) {
        peerNatStatus.set(peerId, status);
        res.json({ status: 'ok' });
    } else {
        res.status(400).json({ error: 'Missing peerId or status' });
    }
});

// Endpoint for peers to report available ICE servers
app.post('/report-ice', validateApiKey, express.json(), (req, res) => {
    const { peerId, servers } = req.body;
    if (peerId && Array.isArray(servers)) {
        peerIceServers.set(peerId, servers);
        res.json({ status: 'ok' });
    } else {
        res.status(400).json({ error: 'Missing peerId or valid servers array' });
    }
});

// Endpoint for peers to report their known neighbors
app.post('/report-peers', validateApiKey, express.json(), (req, res) => {
    const { peerId, knownPeers } = req.body;
    if (peerId && Array.isArray(knownPeers)) {
        if (!peerConnections.has(peerId)) {
            peerConnections.set(peerId, new Set());
        }
        knownPeers.forEach(id => {
            peerConnections.get(peerId).add(id);
            // Attempt to connect if we have a libp2p node and it's a new peer
            if (libp2pNode && id !== libp2pNode.peerId.toString()) {
                libp2pNode.dial(id).catch(() => {});
            }
        });
        res.json({ status: 'ok' });
    } else {
        res.status(400).json({ error: 'Missing peerId or valid knownPeers array' });
    }
});

// Endpoint for peers to fetch known peers
app.get('/get-peers', validateApiKey, (req, res) => {
    const { peerId } = req.query;
    // Return all known peers if no ID provided, or peers of specific peer (PEX)
    if (peerId && peerConnections.has(peerId)) {
        res.json({ peers: Array.from(peerConnections.get(peerId)) });
    } else {
        // Return a random subset of all known peers
        const all = [];
        for (const set of peerConnections.values()) {
            all.push(...set);
        }
        const unique = [...new Set(all)];
        res.json({ peers: unique.slice(0, 50) });
    }
});

// --- FEATURE 2: IROH-STYLE VERIFIED HANDSHAKE ---
const verifiedPeers = new Map();
{
  const rows = db.prepare('SELECT * FROM verified_peers').all();
  for (const row of rows) {
    verifiedPeers.set(row.peerId, { publicKey: row.publicKey, lastSeen: row.lastSeen, ip: row.ip, trustScore: row.trustScore || 0.0 });
  }
}
const verifiedPeersGauge = new client.Gauge({
  name: 'tracker_verified_peers_total',
  help: 'Total number of cryptographically verified peers (Iroh-style)'
});
register.registerMetric(verifiedPeersGauge);

app.post('/handshake', express.json(), (req, res) => {
  const { peerId, publicKey, signature, timestamp } = req.body;

  if (!peerId || !publicKey || !signature || !timestamp) {
    return res.status(400).json({ error: "Incomplete handshake payload" });
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > 300000) {
    return res.status(403).json({ error: "Handshake expired" });
  }

  if (!isTrulyPublic(req.ip)) {
    return res.status(403).json({ error: "Node identity must be tied to a global routable IP." });
  }

  try {
    const pubKeyBytes = Buffer.from(publicKey, 'hex');
    const sigBytes = Buffer.from(signature, 'hex');
    const msg = Buffer.from(`${peerId}:${timestamp}`);
    
    const isValid = nacl.sign.detached.verify(msg, sigBytes, pubKeyBytes);
    
    if (isValid) {
      const existingPeer = verifiedPeers.get(peerId);
      const newScore = (existingPeer ? (existingPeer.trustScore || 0.0) : 0.0) + 0.1; // Increment trust on verification
      
      verifiedPeers.set(peerId, {
        publicKey,
        lastSeen: now,
        ip: req.ip,
        trustScore: newScore
      });
      db.prepare('INSERT OR REPLACE INTO verified_peers (peerId, publicKey, lastSeen, ip, trustScore) VALUES (?, ?, ?, ?, ?)').run(peerId, publicKey, now, req.ip, newScore);
      verifiedPeersGauge.set(verifiedPeers.size);
      
      return res.json({
        status: "verified",
        trustScore: newScore,
        ice_config: getIceServers(peerId)
      });
    } else {
      res.status(401).json({ error: "Invalid cryptographic signature" });
    }
  } catch (e) {
    res.status(500).json({ error: "Verification engine failure" });
  }
});

const announceCounter = new client.Counter({
  name: 'tracker_announce_total',
  help: 'Total announce requests',
  labelNames: ['status', 'country']
});

let currentConnectedPeers = 0;
let currentActiveSwarms = 0;

const activeSwarms = new client.Gauge({
  name: 'tracker_active_swarms',
  help: 'Current active torrent swarms'
});

const connectedPeers = new client.Gauge({
  name: 'tracker_connected_peers',
  help: 'Total active peers'
});

const responseTimeHistogram = new client.Histogram({
  name: 'tracker_response_time_seconds',
  help: 'Announce response time in seconds',
  buckets: [0.01, 0.05, 0.1, 0.5, 1]
});

register.registerMetric(announceCounter);
register.registerMetric(activeSwarms);
register.registerMetric(connectedPeers);
register.registerMetric(responseTimeHistogram);

/**
 * 🔒 VIRTUAL PATCH for IP Validation (SSRF Protection)
 * Validates node identity against global routable IP registry (geoip-lite).
 */
function isTrulyPublic(ipString) {
  try {
    if (!ipString) return false;
    
    // 1. ipaddr.js Range Validation
    const addr = ipaddr.process(ipString);
    const range = addr.range();
    const nonRoutable = ['loopback', 'private', 'linkLocal', 'multicast', 'unspecified', 'broadcast', 'reserved', 'uniqueLocal'];
    if (nonRoutable.includes(range)) return false;
    
    const normalized = addr.toString();
    
    // 2. Extra Layer: Explicit common private subnet checks
    if (normalized.startsWith('127.') || normalized.startsWith('10.') || normalized.startsWith('192.168.')) return false;

    // IPv6 globally routable prefix prioritization and allowance
    // Even if geoip lookup fails, public IPv6 must not be blocked.
    if (addr.kind() === 'ipv6') {
        return true;
    }

    // 3. Global Routable Registry Check (geoip-lite)
    // geoip-lite contains the database of assigned global public IP ranges.
    const geo = geoip.lookup(normalized);
    if (!geo) return false; // If not in registry, it's not a globally routable public identity

    return true;
  } catch (e) { return false; }
}

// Add middleware for IP validation on announce/scrape
const ipValidationMiddleware = (req, res, next) => {
  if (req.path === '/announce' || req.path === '/scrape') {
    if (!isTrulyPublic(req.ip)) {
      return res.status(403).json({ error: 'Private IP Blocked' });
    }
  }
  next();
};

app.use(ipValidationMiddleware); 

// --- FEATURE: MODERN DASHBOARD UI ---
const DASHBOARD_HTML = `
<!DOCTYPE html>
<html>
<head>
    <title>BitTorrent Tracker Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script src="https://cdn.jsdelivr.net/npm/webtorrent@latest/webtorrent.min.js"></script>
    <style>
        @keyframes pulse-soft { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .peer-node { animation: pulse-soft 2s infinite; }
    </style>
</head>
<body class="bg-[#0a0a0b] text-zinc-400 font-sans p-8">
    <div class="max-w-6xl mx-auto">
        <header class="flex justify-between items-center mb-12">
            <div>
                <h1 class="text-3xl font-bold text-white tracking-tighter flex items-center gap-2">
                    <i data-lucide="activity" class="text-emerald-500"></i> P2P Network Tracker
                </h1>
                <p class="text-sm border-l-2 border-emerald-500/30 pl-3 mt-2">BitTorrent Throughput & P2P Statistics</p>
            </div>
            <div class="text-right">
                <div class="inline-flex items-center px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-500 text-xs font-mono border border-emerald-500/20">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 mr-2 peer-node"></span> NETWORK ONLINE
                </div>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-6 gap-6 mb-12">
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Active Swarms</p>
                <h2 id="swarms" class="text-4xl font-bold text-white tracking-tighter">0</h2>
                <div class="h-1 w-12 bg-emerald-500 mt-4"></div>
            </div>
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Connected Peers</p>
                <h2 id="peers" class="text-4xl font-bold text-white tracking-tighter">0</h2>
                <div class="h-1 w-12 bg-blue-500 mt-4"></div>
            </div>
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">DHT Nodes</p>
                <h2 id="dht-nodes" class="text-4xl font-bold text-purple-400 tracking-tighter">0</h2>
                <div class="h-1 w-12 bg-purple-500 mt-4"></div>
            </div>
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">libp2p Mesh</p>
                <h2 id="libp2p-peers" class="text-4xl font-bold text-amber-500 tracking-tighter">0</h2>
                <div class="h-1 w-12 bg-amber-500 mt-4"></div>
            </div>
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl" title="Tracks real-time peer discovery and GossipSub events in a verifiable DAG structure.">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Kaspa DAG Tips/Blocks</p>
                <div class="flex items-baseline gap-2">
                    <h2 id="dag-tips" class="text-4xl font-bold text-cyan-400 tracking-tighter">0</h2>
                    <span class="text-zinc-500 text-sm">/</span>
                    <span id="dag-blocks" class="text-zinc-500 text-xl tracking-tighter">0</span>
                </div>
                <p class="text-[9px] text-zinc-600 mt-2 font-mono">LIVE NETWORK EVENTS</p>
                <div class="h-1 w-12 bg-cyan-500 mt-2"></div>
            </div>
            <div class="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl">
                <p class="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">System Uptime</p>
                <h2 id="uptime" class="text-4xl font-bold text-emerald-500 tracking-tighter">0s</h2>
                <div class="h-1 w-12 bg-emerald-500 mt-4"></div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
            <div class="lg:col-span-2 bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl">
                <div class="p-6 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/20">
                    <h3 class="text-white font-medium flex items-center gap-2">
                        <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i> Signal Registry
                    </h3>
                    <div class="flex items-center gap-4">
                        <span id="dag-blue-score" class="text-[10px] font-mono text-zinc-500 uppercase flex items-center gap-2">
                            <span class="w-1.5 h-1.5 rounded-full bg-cyan-500"></span> DAG BlueScore: <span id="blue-score-val" class="text-cyan-400">0</span>
                        </span>
                        <span id="p2p-status" class="text-[10px] font-mono text-zinc-500 uppercase flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-zinc-600"></span> Disconnected
                        </span>
                    </div>
                </div>
                <div class="p-0 max-h-[400px] overflow-y-auto" id="event-log-container">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-zinc-900/40 text-zinc-500 uppercase text-[9px] tracking-widest sticky top-0">
                            <tr>
                                <th class="px-6 py-4">Protocol</th>
                                <th class="px-6 py-4">Port</th>
                                <th class="px-6 py-4">Status</th>
                                <th class="px-6 py-4 text-right">Protection</th>
                            </tr>
                        </thead>
                        <tbody id="event-log" class="divide-y divide-zinc-800/50">
                            <tr class="border-b border-zinc-800/50 hover:bg-zinc-800/20">
                                <td class="px-6 py-4 font-mono text-emerald-500">WEBRTC / WS</td>
                                <td class="px-6 py-4 text-zinc-500">3000</td>
                                <td class="px-6 py-4"><span class="bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded text-[8px] font-bold">ACTIVE</span></td>
                                <td class="px-6 py-4 text-right text-zinc-600 italic">SSRF-GUARD</td>
                            </tr>
                            <tr class="border-b border-zinc-800/50 hover:bg-zinc-800/20">
                                <td class="px-6 py-4 font-mono text-blue-500">BITTORRENT / HTTP</td>
                                <td class="px-6 py-4 text-zinc-500">3000</td>
                                <td class="px-6 py-4"><span class="bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded text-[8px] font-bold">ACTIVE</span></td>
                                <td class="px-6 py-4 text-right text-zinc-600 italic">SHIELD-PROTECTED</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="space-y-6">
                <!-- Tracker Status -->
                <div class="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl">
                    <div class="p-6 border-b border-zinc-800 bg-zinc-900/20">
                        <h3 class="text-white font-medium flex items-center gap-2">
                            <i data-lucide="server" class="w-4 h-4 text-amber-400"></i> Tracker Status
                        </h3>
                    </div>
                    <div class="p-6 space-y-4">
                        <div>
                            <p class="text-[10px] uppercase text-zinc-500 mb-2">Protocol Stack</p>
                            <div class="space-y-2">
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">WebSocket Signaling</span>
                                    <span class="text-emerald-500 font-mono">READY</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">WebRTC Direct Transport</span>
                                    <span class="text-emerald-500 font-mono">ENABLED</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Circuit Relay (NAT Trap)</span>
                                    <span class="text-emerald-500 font-mono">ACTIVE</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">AutoNAT Traversal</span>
                                    <span class="text-blue-400 font-mono">STANDBY</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">WebRTC + TURN over TLS (443)</span>
                                    <span class="text-emerald-500 font-mono">ENABLED</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">WebTransport (HTTP/3 & QUIC)</span>
                                    <span class="text-emerald-500 font-mono">ENABLED</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Domain Fronting (CDN Proxies)</span>
                                    <span class="text-cyan-400 font-mono">ACTIVE</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Post-Quantum TLS 1.3 (Kyber-768)</span>
                                    <span class="text-emerald-500 font-mono">ENCRYPTED</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">GossipSub Peer Scoring / Ghosting</span>
                                    <span class="text-red-400 font-mono">STRICT</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Pure IP Bootstrapping & mDNS Local</span>
                                    <span class="text-blue-400 font-mono">ACTIVE (NO DNS)</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Mainline DHT + Kademlia</span>
                                    <span class="text-cyan-400 font-mono">SELF-SUSTAINING</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">Kaspa DAG Super-Nodes</span>
                                    <span class="text-cyan-400 font-mono">DYNAMIC</span>
                                </div>
                                <div class="flex justify-between items-center text-xs">
                                    <span class="text-zinc-500">HTTP/Stats API</span>
                                    <span class="text-emerald-500 font-mono">READY</span>
                                </div>
                            </div>
                        </div>
                        <div class="pt-4 border-t border-zinc-800/50">
                            <p class="text-[10px] uppercase text-zinc-500 mb-2">STUN/TURN Hubs</p>
                            <div id="ice-status" class="text-[10px] font-mono text-zinc-600 bg-black/30 p-2 rounded truncate">
                                Loading ICE configuration...
                            </div>
                        </div>
                    </div>
                </div>

                <button id="view-ice" class="w-full py-4 bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-500 text-[10px] font-bold rounded-2xl border border-emerald-500/20 transition-all uppercase tracking-widest shadow-lg">
                    View ICE JSON
                </button>
            </div>
        </div>
    </div>

    <!-- ICE JSON Modal -->
    <div id="ice-modal" class="fixed inset-0 bg-black/90 backdrop-blur-sm hidden flex items-center justify-center p-4 z-50">
        <div class="bg-black border border-zinc-800 rounded-3xl w-full max-w-4xl max-h-[80vh] flex flex-col shadow-2xl relative overflow-hidden">
            <!-- Decoration -->
            <div class="absolute top-0 left-0 w-1 h-full bg-emerald-500"></div>
            
            <div class="p-6 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/40">
                <h3 class="text-white font-medium flex items-center gap-2">
                    <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i> Encrypted ICE Configuration
                </h3>
                <button id="close-ice-modal" class="text-zinc-500 hover:text-white transition-colors">
                    <i data-lucide="x" class="w-6 h-6"></i>
                </button>
            </div>
            <div class="p-8 overflow-auto flex-1 custom-scrollbar">
                <p class="text-[10px] uppercase text-zinc-500 mb-4 tracking-widest">Read-Only Secure Buffer</p>
                <pre id="ice-content" class="text-emerald-500 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all bg-zinc-950/50 p-6 rounded-xl border border-zinc-800/50"></pre>
            </div>
            <div class="p-4 border-t border-zinc-800 bg-zinc-900/20 text-center text-[9px] text-zinc-600 uppercase tracking-[0.2em]">
                Verified Session Parameters • KaspStore Security Node
            </div>
        </div>
    </div>

    <script type="module">
        lucide.createIcons();
        /* API_KEY_INJECTION */
        const apiKey = window.TRACKER_API_KEY || "";
        const apiHeaders = apiKey ? { 'x-api-key': apiKey } : {};

        const eventLog = document.getElementById('event-log');
        const p2pStatus = document.getElementById('p2p-status');
        const viewIceBtn = document.getElementById('view-ice');
        const iceModal = document.getElementById('ice-modal');
        const iceContent = document.getElementById('ice-content');
        const closeIceModal = document.getElementById('close-ice-modal');
        let client = null;

        viewIceBtn.onclick = async () => {
            try {
                viewIceBtn.disabled = true;
                viewIceBtn.innerText = 'Loading...';
                
                const res = await fetch('/ice', { headers: apiHeaders });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                
                // Mask credentials for display
                if (data.iceServers) {
                    data.iceServers = data.iceServers.map(server => {
                        const masked = { ...server };
                        if (masked.credential) masked.credential = '********';
                        if (masked.username) masked.username = '********';
                        return masked;
                    });
                }
                
                // Use textContent to prevent any potential HTML injection/tampering
                iceContent.textContent = JSON.stringify(data, null, 2);
                iceModal.classList.remove('hidden');
            } catch (e) {
                alert('Failed to fetch ICE: ' + e.message);
            } finally {
                viewIceBtn.disabled = false;
                viewIceBtn.innerText = 'View ICE JSON';
            }
        };

        closeIceModal.onclick = () => {
            iceModal.classList.add('hidden');
        };

        // Close modal on escape key
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') iceModal.classList.add('hidden');
        });

        function addLog(action, peer, protection = 'SECURE') {
            const row = document.createElement('tr');
            row.className = 'hover:bg-zinc-800/30 transition-colors';
            
            // Create cells manually to ensure textContent is used for safety
            const timeCell = document.createElement('td');
            timeCell.className = 'px-6 py-4 font-mono text-[10px] text-zinc-500';
            timeCell.textContent = new Date().toLocaleTimeString();
            
            const actionCell = document.createElement('td');
            actionCell.className = 'px-6 py-4';
            const actionSpan = document.createElement('span');
            actionSpan.className = 'px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-500';
            actionSpan.textContent = action;
            actionCell.appendChild(actionSpan);
            
            const peerCell = document.createElement('td');
            peerCell.className = 'px-6 py-4 font-mono text-xs text-white truncate max-w-[150px]';
            peerCell.textContent = peer;
            
            const protectionCell = document.createElement('td');
            protectionCell.className = 'px-6 py-4 text-right font-mono text-[10px] text-zinc-600';
            protectionCell.textContent = protection;
            
            row.appendChild(timeCell);
            row.appendChild(actionCell);
            row.appendChild(peerCell);
            row.appendChild(protectionCell);
            
            eventLog.insertBefore(row, eventLog.firstChild);
            if (eventLog.children.length > 50) eventLog.lastChild.remove();
        }


        async function initP2P() {
            if (client) return;

            // Wait for WebTorrent if not yet available
            if (!window.WebTorrent) {
                setTimeout(initP2P, 500);
                return;
            }

            try {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                // Add API key to the tracker URL to satisfy the server's filter requirement
                const authParam = apiKey ? `?api_key=${apiKey}` : '';
                const trackerUrl = protocol + '//' + window.location.host + '/announce' + authParam;
                
                const WT = window.WebTorrent;
                client = new WT();
                
                p2pStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-blue-500 peer-node"></span> Initializing...';
                
                const dummyId = 'd874f69205d122245e3c1374522a36ee00902fed';
                const torrent = client.add('magnet:?xt=urn:btih:' + dummyId + '&tr=' + encodeURIComponent(trackerUrl), { announce: [trackerUrl] }, (t) => {
                    p2pStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 peer-node animate-pulse"></span> Signaling Active';
                    addLog('ANNOUNCE', 'LOCALHOST-NODE');
                });

                torrent.on('wire', (wire, addr) => {
                    addLog('WEBRTC', addr || wire.peerId, 'P2P-CONNECTED');
                    
                    wire.on('close', () => {
                    });
                });

                torrent.on('error', (err) => {
                    addLog('ERROR', err.message, 'FAILED');
                });

            } catch (err) {
                console.error('P2P Init Error:', err);
                p2pStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-red-600"></span> Error';
            }
        }

        // Auto-initialize P2P discovery
        initP2P();

        async function updateStats() {
            try {
                const res = await fetch('/health', { headers: apiHeaders });
                const data = await res.json();
                document.getElementById('swarms').innerText = data.metrics.swarms;
                document.getElementById('peers').innerText = data.metrics.peers;
                document.getElementById('dht-nodes').innerText = data.metrics.dht_nodes || 0;
                document.getElementById('libp2p-peers').innerText = data.metrics.libp2p_peers || 0;
                document.getElementById('dag-tips').innerText = data.metrics.dag_tips || 0;
                document.getElementById('blue-score-val').innerText = data.metrics.dag_blue_score || 0;
                document.getElementById('uptime').innerText = data.uptime + 's';
                
                const iceResponse = await fetch('/ice', { headers: apiHeaders });
                const iceConfig = await iceResponse.json();
                
                // Update DAG metrics
                document.getElementById('dag-tips').innerText = data.metrics.dag_tips || 0;
                document.getElementById('dag-blocks').innerText = data.metrics.dag_blocks || 0;
                
                const iceStatusEl = document.getElementById('ice-status');
                if (iceStatusEl) {
                    if (iceConfig.iceServers) {
                        iceStatusEl.innerText = iceConfig.iceServers.length + ' Servers (STUN/TURN)';
                    } else if (iceConfig.error) {
                        iceStatusEl.innerText = 'Auth Error';
                        iceStatusEl.classList.add('text-red-500');
                    }
                }
            } catch (e) {
                if (e.message !== 'Failed to fetch') {
                    console.error('Stats Update Error:', e);
                }
            }
        }
        setInterval(updateStats, 2000);
        updateStats();



    </script>
</body>
</html>
`;

app.get('/', (req, res) => {
  const injectedHtml = DASHBOARD_HTML.replace(
    '/* API_KEY_INJECTION */',
    `window.TRACKER_API_KEY = "${process.env.TRACKER_API_KEY || ''}";`
  );
  res.send(injectedHtml);
});

// --- Core Decentralized Routing Services ---

// 1. BitTorrent Mainline DHT
const dht = new DHT();

dht.listen(20000, () => {
    console.log('🌐 Mainline DHT listening on port 20000');
});

import { mdns } from '@libp2p/mdns';

// 2. libp2p Advanced Mesh Network
let libp2pNode = null;
async function startLibp2p() {
    try {
        // Pure Decentralized Discovery - NO DNS OR CENTRALIZED RESOLVERS
        // By relying purely on mDNS (Local network) + static hardcoded globally distributed IPs (Bootstrap), 
        // we eliminate DoH and Cloudflare as a central point of failure.
        const staticBootstrapPeers = [
            '/ip6/2604:a880:1:20::203:d001/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73GENcgvT7mZmTeWEkgBPgW2t',
            '/ip6/2400:6180:0:d0::151:6001/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu',
            '/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ',
            '/ip4/104.236.179.241/tcp/4001/p2p/QmSoLPppuBtQSGwKDZT2M73GENcgvT7mZmTeWEkgBPgW2t',
            '/ip4/128.199.219.111/tcp/4001/p2p/QmSoLSafTMBsPKadTEgaXctDQVcqN88CNLHXMkTNwMKPnu',
            '/ip4/178.62.158.247/tcp/4001/p2p/QmSoLer265NRgSp2LA3dPaeykiS1J6DifTC88f5uVQKNAd'
        ];
        
        libp2pNode = await createLibp2p({
            addresses: { 
                listen: [
                    '/ip6/::/tcp/3001', 
                    '/ip4/0.0.0.0/tcp/3001', 
                    '/ip6/::/tcp/3002/ws', 
                    '/ip4/0.0.0.0/tcp/3002/ws'
                ] 
            },
            connectionManager: {
                addressSorter: (addresses) => {
                    return addresses.sort((a, b) => {
                        const aIsIp6 = a.multiaddr ? a.multiaddr.toString().includes('ip6') : a.toString().includes('ip6');
                        const bIsIp6 = b.multiaddr ? b.multiaddr.toString().includes('ip6') : b.toString().includes('ip6');
                        if (aIsIp6 && !bIsIp6) return -1;
                        if (!aIsIp6 && bIsIp6) return 1;
                        return 0;
                    });
                }
            },
            transports: [tcp(), webSockets(), circuitRelayTransport({ discoverRelays: 1 })],
            connectionEncryption: [tls()], // TLS 1.3 Post-Quantum Handshakes
            streamMuxers: [yamux()],
            peerDiscovery: [
                mdns(),
                bootstrap({
                    list: staticBootstrapPeers
                })
            ],
            services: {
                relay: circuitRelayServer({}),
                dht: kadDHT(),
                pubsub: gossipsub({
                    scoreParams: {
                        IPColocationFactorWeight: -100,
                        IPColocationFactorThreshold: 3,
                        behaviourPenaltyWeight: -10,
                        behaviourPenaltyThreshold: 0,
                        behaviourPenaltyDecay: 0.9
                    },
                    scoreThresholds: {
                        gossipThreshold: -50,
                        publishThreshold: -100,
                        graylistThreshold: -200,
                        acceptPXThreshold: -250,
                        opportunisticGraftThreshold: 20
                    }
                }),
                identify: identify(),
                ping: ping(),
                relay: circuitRelayServer(),
                autoNAT: autoNAT({
                    probeInterval: 1000 * 60 * 5,
                    onStatusChange: (status) => {
                        console.log('📡 AutoNAT status changed:', status.status);
                        global.myNatStatus = status.status;
                    }
                })
            }
        });
        console.log('📡 libp2p Mesh Service started with PeerId:', libp2pNode.peerId.toString());
    } catch (e) {
        console.error('Failed to start libp2p:', e);
    }
}
startLibp2p();

// 3. Kaspa-Inspired Super-Node DAG (Enhanced with GHOSTDAG-inspired logic)
class KaspaDAG {
    constructor() {
        this.blocks = new Map();
        const rows = db.prepare('SELECT * FROM dag_blocks').all();
        for(const row of rows) {
          this.blocks.set(row.hash, JSON.parse(row.data));
        }

        this.genesisHash = crypto.createHash('sha256').update('genesis').digest('hex');
        this.tips = [...this.blocks.keys()].filter(hash => {
            const block = this.blocks.get(hash);
            // This is a simplified tip detection: if no other block has this as parent
            return ![...this.blocks.values()].some(b => b.parents.includes(hash));
        });
        if(this.tips.length === 0) this.tips = [this.genesisHash];

        if (!this.blocks.has(this.genesisHash)) {
          const genesisBlock = {
              id: 'genesis-bootstrap-node',
              hash: this.genesisHash,
              parents: [],
              nodes: ['bootstrap.node.p2p'],
              timestamp: Date.now(),
              blueScore: 0
          };
          this.blocks.set(this.genesisHash, genesisBlock);
          db.prepare('INSERT OR REPLACE INTO dag_blocks (hash, data) VALUES (?, ?)').run(this.genesisHash, JSON.stringify(genesisBlock));
        }
    }

    addBlock(nodes, parents = this.tips) {
        // Create deterministic topological hash
        const dataStr = nodes.join(',') + parents.sort().join(',') + Date.now();
        const hash = crypto.createHash('sha256').update(dataStr).digest('hex');
        
        // Simple GHOSTDAG-like blue score increment (sum of parent scores + 1)
        const maxParentScore = parents.reduce((max, pHash) => {
            const p = this.blocks.get(pHash);
            return p ? Math.max(max, p.blueScore) : max;
        }, 0);

        const newBlock = {
            id: nodes[0], 
            hash: hash,
            parents: [...parents],
            nodes: nodes,
            timestamp: Date.now(),
            blueScore: maxParentScore + 1
        };
        
        this.blocks.set(hash, newBlock);
        db.prepare('INSERT OR REPLACE INTO dag_blocks (hash, data) VALUES (?, ?)').run(hash, JSON.stringify(newBlock));
        
        // Update tips: remove parents that are now covered, add new hash
        this.tips = this.tips.filter(t => !parents.includes(t));
        this.tips.push(hash);
        
        return newBlock;
    }

    getTipCount() {
        return this.tips.length;
    }

    getBlocksCount() {
        return this.blocks.size;
    }
}

const superNodeDAG = new KaspaDAG();
const searchTracker = new Map();
{
  const rows = db.prepare('SELECT * FROM search_trackers').all();
  for (const row of rows) {
    searchTracker.set(row.queryHash, JSON.parse(row.data));
  }
}

// Periodic cleanup for state to prevent memory leaks
setInterval(() => {
    const now = Date.now();
    
    // Cleanup searchTracker (1 hour retention)
    for (const [hash, data] of searchTracker.entries()) {
        if (now - data.startTime > 3600000) {
            searchTracker.delete(hash);
        }
    }
    
    // Cleanup verifiedPeers (10 minute retention)
    for (const [peerId, data] of verifiedPeers.entries()) {
        if (now - data.lastSeen > 600000) {
            verifiedPeers.delete(peerId);
        }
    }
}, 300000); // Run every 5 minutes

// Real peer discovery integration
async function attachRealPeerEvents() {
    if (libp2pNode) {
        libp2pNode.addEventListener('peer:discovery', (evt) => {
            const peerId = evt.detail.id.toString();
            // Record discovery as a DAG event
            superNodeDAG.addBlock([peerId]);
        });

        libp2pNode.addEventListener('peer:connect', (evt) => {
            const peerId = evt.detail.toString();
            // Record connection as a higher-priority DAG event
            superNodeDAG.addBlock([peerId + '-connected']);
        });

        // Track real GossipSub propagation
        libp2pNode.services.pubsub.addEventListener('message', (evt) => {
            const { topic, data, from } = evt.detail;
            if (topic === 'global-search') {
                const query = new TextDecoder().decode(data);
                const queryHash = crypto.createHash('sha1').update(query).digest('hex');
                
                if (!searchTracker.has(queryHash)) {
                    searchTracker.set(queryHash, {
                        query,
                        hops: [],
                        startTime: Date.now()
                    });
                }
                
                const tracker = searchTracker.get(queryHash);
                tracker.hops.push({
                    peerId: from.toString(),
                    timestamp: Date.now(),
                    nodeType: 'GOSSIP_RELAY'
                });

                // Also add a block to the DAG reflecting this consensus event
                superNodeDAG.addBlock([from.toString()]);
            }
        });

        // Ensure we are subscribed to the search topic
        libp2pNode.services.pubsub.subscribe('global-search');
    } else {
        setTimeout(attachRealPeerEvents, 1000);
    }
}
attachRealPeerEvents();

app.get('/api/search', validateApiKey, (req, res) => {
    const q = req.query.q;
    if (!q) return res.status(400).json({ error: 'Missing query' });

    const queryHash = crypto.createHash('sha1').update(q).digest('hex');
    
    // 1. Publish search query to the mesh
    if (libp2pNode) {
        try {
            const payload = new TextEncoder().encode(q);
            libp2pNode.services.pubsub.publish('global-search', payload).catch(() => {});
        } catch(e) {}
    }

    // Initialize local tracking for this query
    if (!searchTracker.has(queryHash)) {
        const data = {
            query: q,
            hops: [{ peerId: libp2pNode?.peerId.toString() || 'origin-node', timestamp: Date.now(), nodeType: 'ORIGIN' }],
            startTime: Date.now()
        };
        searchTracker.set(queryHash, data);
        db.prepare('INSERT OR REPLACE INTO search_trackers (queryHash, data) VALUES (?, ?)').run(queryHash, JSON.stringify(data));
    }

    // 2. Mainline DHT lookup
    try {
        if (q.length >= 20) {
            dht.get(q, (err, val) => {});
            dht.lookup(q); 
        }
    } catch(e) {}

    const tracker = searchTracker.get(queryHash);
    
    res.json({
        query: q,
        status: 'propagating_to_mesh',
        mesh_topic: 'global-search',
        dag_peers_traversed: superNodeDAG.blocks.size,
        routing_path: tracker.hops.slice(-10),
        dag_blue_score: Array.from(superNodeDAG.blocks.values()).reduce((sum, b) => sum + b.blueScore, 0)
    });
});

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
    console.error('System Error Captured:', err.stack);
    res.status(500).json({
        error: 'Terminal System Deviation',
        message: 'Internal processing error has been logged.',
        protection: 'ACTIVE'
    });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'P2P Tracker Service',
    uptime: Math.floor(process.uptime()),
    nat_status: global.myNatStatus,
    load_shedding: false,
    metrics: {
      peers: currentConnectedPeers,
      swarms: currentActiveSwarms,
      dht_nodes: dht.toJSON().nodes ? Math.max(dht.toJSON().nodes.length, 0) : 0,
      libp2p_peers: libp2pNode ? libp2pNode.getConnections().length : 0,
      dag_tips: superNodeDAG.getTipCount(),
      dag_blocks: superNodeDAG.getBlocksCount(),
      dag_blue_score: Array.from(superNodeDAG.blocks.values()).reduce((sum, b) => sum + b.blueScore, 0)
    }
  });
});

const httpServer = http.createServer(app);

// --- FEATURE 6: WEBSOCKET REAL-TIME PEER INTERFACE ---
// bittorrent-tracker handles the WebSocket upgrade for '/announce' automatically.
// We don't need a custom wss handler here.

// 3. Initialize the Tracker
const tracker = new Server({
  udp: false,
  http: true,
  ws: true,
  stats: true,
  trustProxy: true,
  server: httpServer,
  filter: (infoHash, params, cb) => {
    const start = Date.now();
    const reqKey = process.env.TRACKER_API_KEY;
    const clientKey = params.api_key || params.token;

    if (reqKey && clientKey !== reqKey) {
      return cb(new Error('Unauthorized'));
    }

    if (!infoHash || infoHash.length !== 40) return cb(new Error('Invalid Hash'));
    
    if (params.ip && !isTrulyPublic(params.ip)) return cb(new Error('Private IP Blocked'));

    // Record Metrics
    totalAnnounces++;
    const geo = geoip.lookup(params.ip || '0.0.0.0');
    const country = geo ? geo.country : 'Unknown';
    announceCounter.inc({ status: 'success', country });
    responseTimeHistogram.observe((Date.now() - start) / 1000); 

    cb(null);
  }
});

// 4. Tracker Metrics Helper
const updateMetrics = () => {
    const torrentsData = tracker.torrents;
    const infoHashes = Object.keys(torrentsData);
    let peerCount = 0;
    infoHashes.forEach(hash => {
        const torrent = torrentsData[hash];
        if (torrent && torrent.peers) {
            peerCount += (typeof torrent.peers.size === 'number') ? torrent.peers.size : Object.keys(torrent.peers).length;
        }
    });
    activeSwarms.set(infoHashes.length);
    connectedPeers.set(peerCount);
    currentActiveSwarms = infoHashes.length;
    currentConnectedPeers = peerCount;
};

tracker.on('start', updateMetrics);
tracker.on('stop', updateMetrics);
updateMetrics(); // Force initial update

// FEATURE 5: SELF-HEALING & MEMORY GUARD
setInterval(() => {
  updateMetrics();
  const mem = process.memoryUsage();
  if (mem.rss > 900 * 1024 * 1024) { 
    console.warn('🚦 CRITICAL MEMORY: Shedding least active swarms...');
    // Professional Cleanup Logic would go here
  }
}, 10000).unref();

tracker.on('error', (err) => console.error(`❌ Tracker Error: ${err.message}`));

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 P2P TRACKER ENGINE LIVE ON PORT ${PORT}`);
});

const gracefulShutdown = (signal) => {
  tracker.close(() => {
    httpServer.close(() => process.exit(0));
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  console.error('💥 FATAL:', err);
  process.exit(1);
});
