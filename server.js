const http = require('http');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const server = http.createServer();
const io = new Server(server, {
  cors: { origin: "*" }
});

const swarms = new Map();

io.on('connection', (socket) => {
  console.log(`[P2P Node] Inbound Peer Stream Linked: ${socket.id}`);

  socket.on('join-swarm', (peerData) => {
    const { topic, peerId, addresses } = peerData;
    
    if (!swarms.has(topic)) {
      swarms.set(topic, new Map());
    }
    
    const topicSwarm = swarms.get(topic);
    topicSwarm.set(socket.id, { peerId, addresses, timestamp: Date.now() });
    
    console.log(`[Swarm] Peer ${peerId} registered for topic: ${topic}`);

    const clusterNodes = Array.from(topicSwarm.values());
    io.to(socket.id).emit('swarm-topology', clusterNodes);
    socket.broadcast.to(topic).emit('peer-announced', { peerId, addresses });
    
    socket.join(topic);
  });

  socket.on('disconnect', () => {
    swarms.forEach((topicSwarm, topic) => {
      if (topicSwarm.has(socket.id)) {
        const peer = topicSwarm.get(socket.id);
        topicSwarm.delete(socket.id);
        console.log(`[P2P Node] Peer disconnected: ${peer.peerId}`);
        socket.broadcast.to(topic).emit('peer-left', { peerId: peer.peerId });
      }
    });
  });
});

server.listen(PORT, () => {
  console.log(`🚀 KaspStore P2P Tracker initialized on port ${PORT}`);
  console.log(`🔗 Listening for live decentralized routing events...`);
});
