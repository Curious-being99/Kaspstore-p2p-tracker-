import { gossipsub } from '@chainsafe/libp2p-gossipsub';
console.log(gossipsub().call ? "Needs args possibly" : "");
