import { createServer } from "http";
import { Server, Socket } from "socket.io";

interface Peer {
  peerId: string;
  address: string;
  lastSeen: number;
}

const PORT = process.env.PORT || 3000;
const httpServer = createServer();
const io = new Server(httpServer, { cors: { origin: "*" } });

const swarms = new Map<string, Map<string, Peer>>();

io.on("connection", (socket: Socket) => {
  console.log(`[P2P Node] Inbound Peer Stream: ${socket.id}`);

  socket.on("sync-request", (data: { namespace: string; peerId: string; address: string }) => {
    const { namespace, peerId, address } = data;
    if (!swarms.has(namespace)) swarms.set(namespace, new Map());
    
    const swarm = swarms.get(namespace)!;
    swarm.set(socket.id, { peerId, address, lastSeen: Date.now() });
    
    console.log(`[Swarm: ${namespace}] Peer ${peerId} registered.`);
    socket.emit("topology-update", Array.from(swarm.values()));
    socket.join(namespace);
  });

  socket.on("disconnect", () => {
    swarms.forEach((swarm, namespace) => {
      if (swarm.has(socket.id)) {
        swarm.delete(socket.id);
        io.to(namespace).emit("peer-left", { id: socket.id });
      }
    });
  });
});

httpServer.listen(PORT, () => {
  console.log("--------------------------------------------------");
  console.log(`🚀 KaspStore Tracker: Fresh TS Build on port ${PORT}`);
  console.log("--------------------------------------------------");
});
