import React, { useState, useEffect } from 'react';
import { Activity, Zap, Server, ShieldCheck, X, Globe, Cpu, Database, Terminal, Copy } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

export default function App() {
  const [metrics, setMetrics] = useState<any>(null);
  const [iceServers, setIceServers] = useState<any[]>([]);
  const [showIceModal, setShowIceModal] = useState(false);
  const [loadingIce, setLoadingIce] = useState(false);
  const [radKey, setRadKey] = useState("");
  const [isMirroring, setIsMirroring] = useState(false);

  const startMirroring = async () => {
    if (!radKey) {
      alert("Please paste your Radicle private key (base64) first.");
      return;
    }
    setIsMirroring(true);
    
    try {
      const headers: any = { 'Content-Type': 'application/json' };
      if (apiKey) headers['x-api-key'] = apiKey;
      
      const res = await fetch(`${apiUrl}/api/mirror`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ radKey })
      });
      
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      
      alert(`${data.message}\nCID: ${data.cid}\nSeed: ${data.seed}`);
      setRadKey(""); // Clear key after successful mirror
      fetchMetrics(); // Refresh stats immediately
    } catch (err: any) {
      alert(`Mirroring failed: ${err.message}`);
    } finally {
      setIsMirroring(false);
    }
  };

  const apiKey = (window as any).TRACKER_API_KEY || import.meta.env.VITE_TRACKER_API_KEY || "";
  const apiUrl = import.meta.env.VITE_API_URL || "";

  const fetchMetrics = async () => {
    try {
      const headers: any = {};
      if (apiKey) headers['x-api-key'] = apiKey;
      
      const res = await fetch(`${apiUrl}/health`, { headers });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setMetrics(data);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const fetchIceServers = async () => {
    setLoadingIce(true);
    try {
      const headers: any = {};
      if (apiKey) headers['x-api-key'] = apiKey;
      
      const res = await fetch(`${apiUrl}/ice`, { headers });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setIceServers(data.iceServers || []);
      setShowIceModal(true);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoadingIce(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0a0b] text-zinc-400 font-sans p-4 md:p-8 selection:bg-emerald-500/30">
      <div className="max-w-6xl mx-auto">
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-12 gap-4">
          <div>
            <motion.h1 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-3xl font-bold text-white tracking-tighter flex items-center gap-2"
            >
              <Activity className="text-emerald-500 w-8 h-8" /> P2P Network Tracker
            </motion.h1>
            <p className="text-sm border-l-2 border-emerald-500/30 pl-3 mt-2">BitTorrent Throughput & P2P Statistics</p>
          </div>
          <div className="flex items-center gap-4">
            <div className={`inline-flex items-center px-3 py-1 rounded-full ${error ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'} text-xs font-mono border`}>
              <span className={`w-2 h-2 rounded-full mr-2 animate-pulse ${error ? 'bg-red-500' : 'bg-emerald-500'}`}></span>
              {error ? 'CONNECTION LOST' : 'NETWORK ONLINE'}
            </div>
          </div>
        </header>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard title="Active Swarms" value={metrics?.metrics?.swarms || 0} color="emerald" icon={Globe} />
          <StatCard title="Connected Peers" value={metrics?.metrics?.peers || 0} color="blue" icon={Cpu} />
          <StatCard title="DHT Nodes" value={metrics?.metrics?.dht_nodes || 0} color="purple" icon={Database} />
          <StatCard title="libp2p Mesh" value={metrics?.metrics?.libp2p_peers || 0} color="amber" icon={Zap} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl backdrop-blur-md">
              <div className="p-6 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/20">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Zap className="w-4 h-4 text-emerald-400" /> Signal Registry
                </h3>
                <div className="flex items-center gap-4">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-500"></span> DAG BlueScore: <span className="text-cyan-400">{metrics?.metrics?.dag_blue_score || 0}</span>
                  </span>
                </div>
              </div>
              <div className="p-0 overflow-x-auto">
                <table className="w-full text-left text-xs whitespace-nowrap">
                  <thead className="bg-zinc-900/40 text-zinc-500 uppercase text-[9px] tracking-widest sticky top-0">
                    <tr>
                      <th className="px-6 py-4">Protocol</th>
                      <th className="px-6 py-4">Port</th>
                      <th className="px-6 py-4">Status</th>
                      <th className="px-6 py-4 text-right">Protection</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/50">
                    <TableRow protocol="WEBRTC / WS" port="3000" status="ACTIVE" protection="SSRF-GUARD" />
                    <TableRow protocol="BITTORRENT / HTTP" port="3000" status="ACTIVE" protection="SHIELD-PROTECTED" />
                    <TableRow protocol="LIBP2P / MESH" port="4001" status="ACTIVE" protection="END-TO-END" />
                  </tbody>
                </table>
              </div>
            </div>

            <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl backdrop-blur-md">
              <div className="p-6 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/20">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" /> Deploy Your Own Node
                </h3>
              </div>
              <div className="p-6">
                <p className="text-[11px] text-zinc-400 mb-4 uppercase tracking-widest font-medium">Clone and run the open-source Kaspstore P2P Tracker</p>
                <div className="flex gap-2 items-stretch">
                  <div className="flex-1 bg-black border border-zinc-800 p-3 rounded-xl flex items-center overflow-x-auto">
                    <code className="text-emerald-500 font-mono text-xs whitespace-nowrap">
                      git clone https://github.com/Curious-being99/Kaspstore-p2p-tracker-.git
                    </code>
                  </div>
                  <button 
                    onClick={() => {
                        navigator.clipboard.writeText('git clone https://github.com/Curious-being99/Kaspstore-p2p-tracker-.git');
                        alert('Clone command copied to clipboard!');
                    }}
                    className="bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-500 border border-emerald-500/20 px-4 py-3 rounded-xl text-xs font-bold transition-all uppercase tracking-widest flex items-center gap-2 active:scale-95"
                    title="Copy command"
                  >
                    <Copy className="w-4 h-4" /> Copy
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl backdrop-blur-md">
              <div className="p-6 border-b border-zinc-800 bg-zinc-900/20">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Server className="w-4 h-4 text-amber-400" /> System Uptime
                </h3>
              </div>
              <div className="p-6">
                <h2 className="text-4xl font-bold text-emerald-500 tracking-tighter">{metrics?.uptime || 0}s</h2>
                <div className="h-1 w-12 bg-emerald-500 mt-4 rounded-full"></div>
              </div>
            </div>

            <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl backdrop-blur-md">
              <div className="p-6 border-b border-zinc-800 bg-zinc-900/20">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <Globe className="w-4 h-4 text-emerald-400" /> Decentralized Mirroring
                </h3>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-zinc-500 uppercase">IPFS (Pinata)</span>
                    <span className="text-[10px] font-bold text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">STANDBY</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-zinc-500 uppercase">Radicle P2P</span>
                    <span className="text-[10px] font-bold text-amber-500 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">WAITING FOR KEYS</span>
                  </div>
                </div>
                
                <div className="mt-6 p-4 rounded-xl bg-black/40 border border-zinc-800/50">
                  <p className="text-[9px] text-zinc-400 uppercase mb-2 tracking-widest flex items-center gap-2">
                    <ShieldCheck className="w-3 h-3 text-emerald-500" /> Termux / CLI Setup
                  </p>
                  <code className="text-[10px] text-emerald-500/80 block break-all font-mono leading-relaxed">
                    # Next step in your terminal:<br/>
                    cat ~/.radicle/keys/radicle.key | base64 | tr -d '\n'
                  </code>
                  
                  <div className="mt-4">
                    <label className="text-[9px] text-zinc-500 uppercase mb-1 block">Paste Base64 Key Here</label>
                    <input 
                      type="password"
                      value={radKey}
                      onChange={(e) => setRadKey(e.target.value)}
                      placeholder="Paste your key..."
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-[10px] text-emerald-500 font-mono focus:outline-none focus:border-emerald-500/50 transition-colors"
                    />
                  </div>
                </div>
                
                <button 
                  onClick={startMirroring}
                  disabled={isMirroring}
                  className="w-full mt-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-zinc-700 text-black text-[10px] font-bold rounded-xl transition-all uppercase tracking-widest shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                >
                  {isMirroring ? 'Initiating Mirror...' : 'Mirror Now'}
                </button>
              </div>
            </div>

            <button 
              onClick={fetchIceServers}
              disabled={loadingIce}
              className="w-full py-4 bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-500 text-[10px] font-bold rounded-2xl border border-emerald-500/20 transition-all uppercase tracking-widest shadow-lg active:scale-95 disabled:opacity-50"
            >
              {loadingIce ? 'Loading Configuration...' : 'View ICE Registry'}
            </button>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {showIceModal && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4 z-50"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="bg-black border border-zinc-800 rounded-3xl w-full max-w-4xl max-h-[80vh] flex flex-col shadow-2xl relative overflow-hidden"
            >
              <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500"></div>
              <div className="p-6 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/40">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" /> Encrypted ICE Configuration
                </h3>
                <button onClick={() => setShowIceModal(false)} className="text-zinc-500 hover:text-white transition-colors">
                  <X className="w-6 h-6" />
                </button>
              </div>
              <div className="p-8 overflow-auto flex-1 font-mono text-xs text-emerald-500 bg-zinc-950/50 leading-relaxed whitespace-pre-wrap break-all">
                {JSON.stringify({ iceServers }, null, 2)}
              </div>
              <div className="p-4 border-t border-zinc-800 bg-zinc-900/20 text-center text-[9px] text-zinc-600 uppercase tracking-[0.2em]">
                Verified Session Parameters • Secure Node Buffer
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function StatCard({ title, value, color, icon: Icon }: any) {
  const colors: any = {
    emerald: 'text-emerald-400 bg-emerald-500',
    blue: 'text-blue-400 bg-blue-500',
    purple: 'text-purple-400 bg-purple-500',
    amber: 'text-amber-400 bg-amber-500'
  };

  return (
    <motion.div 
      whileHover={{ y: -5 }}
      className="bg-zinc-900/50 border border-zinc-800 p-6 rounded-2xl shadow-xl backdrop-blur-sm"
    >
      <div className="flex justify-between items-start mb-2">
        <p className="text-[9px] uppercase tracking-widest text-zinc-500">{title}</p>
        <Icon className={`w-4 h-4 ${colors[color].split(' ')[0]}`} />
      </div>
      <h2 className={`text-4xl font-bold tracking-tighter ${colors[color].split(' ')[0]}`}>{value}</h2>
      <div className={`h-1 w-12 mt-4 rounded-full ${colors[color].split(' ')[1]}`}></div>
    </motion.div>
  );
}

function TableRow({ protocol, port, status, protection }: any) {
  return (
    <tr className="border-b border-zinc-800/50 hover:bg-zinc-800/20 transition-colors">
      <td className="px-6 py-4 font-mono text-emerald-500">{protocol}</td>
      <td className="px-6 py-4 text-zinc-500">{port}</td>
      <td className="px-6 py-4">
        <span className="bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded text-[8px] font-bold border border-emerald-500/20">
          {status}
        </span>
      </td>
      <td className="px-6 py-4 text-right text-zinc-600 italic">{protection}</td>
    </tr>
  );
}

