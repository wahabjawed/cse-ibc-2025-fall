import hashlib
import json
import time
import ecdsa
import base58
import socket
import threading
import sys
import uuid  #transaction IDs

class Block:
    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.merkle_root = self.compute_merkle_root()
        self.hash = self.compute_hash()
    
    def compute_merkle_root(self):
        if not self.transactions:
            return hashlib.sha256(b"").hexdigest()  # Return a hash of empty string instead of empty string
        transaction_hashes = [hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in self.transactions]
        while len(transaction_hashes) > 1:
            if len(transaction_hashes) % 2 == 1:
                transaction_hashes.append(transaction_hashes[-1])
            transaction_hashes = [
                hashlib.sha256((transaction_hashes[i] + transaction_hashes[i + 1]).encode()).hexdigest()
                for i in range(0, len(transaction_hashes), 2)
            ]
        return transaction_hashes[0]
    
    def compute_hash(self):
        block_data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root
        }, sort_keys=True)
        return hashlib.sha256(block_data.encode()).hexdigest()

def generate_bitcoin_address():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key().to_string()
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    extended_ripemd160 = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    address = base58.b58encode(binary_address).decode()
    return address, private_key

class Blockchain:
    difficulty = 4  
    
    def __init__(self):
        self.chain = []
        self.peers = set()
        self.transactions = []
        self.processed_tx_ids = set()  # Track processed transaction IDs to prevent loops
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = Block(0, [], "0")
        self.proof_of_work(genesis_block)  #genesis block
        self.chain.append(genesis_block)
    
    def add_block(self):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), self.transactions.copy(), previous_block.hash)  # Use copy of transactions
        self.proof_of_work(new_block)
        self.chain.append(new_block)
        
        for tx in self.transactions:
            if 'tx_id' in tx:
                self.processed_tx_ids.add(tx['tx_id'])
        
        self.transactions = []  
        return new_block
    
    def proof_of_work(self, block):
        print(f"Mining block {block.index}...")
        while not block.hash.startswith("0" * self.difficulty):
            block.nonce += 1
            block.hash = block.compute_hash()
            if block.nonce % 10000 == 0:  
                print(f"Nonce: {block.nonce}, Current hash: {block.hash[:10]}...")
        print(f"Block mined! Hash: {block.hash}")
    
    def is_chain_valid(self, chain_to_validate=None):
        chain = chain_to_validate if chain_to_validate is not None else self.chain
        
        for i in range(1, len(chain)):
            prev_block = chain[i - 1]
            curr_block = chain[i]
            
            curr_block_check = Block(curr_block.index, curr_block.transactions, curr_block.previous_hash)
            curr_block_check.nonce = curr_block.nonce
            curr_block_check.timestamp = curr_block.timestamp
            
            if curr_block.hash != curr_block_check.compute_hash():
                print(f"Invalid hash on block {curr_block.index}")
                return False
                
            if curr_block.previous_hash != prev_block.hash:
                print(f"Invalid previous hash on block {curr_block.index}")
                return False
                
            if not curr_block.hash.startswith("0" * self.difficulty):
                print(f"Proof of work not satisfied for block {curr_block.index}")
                return False
                
        return True
    
    def add_peer(self, peer_address):
        if peer_address not in self.peers:
            self.peers.add(peer_address)
            print(f"Added peer: {peer_address}")
    
    def sync_chain(self, new_chain_data):
        try:
            # Convert JSON data back to Block objects
            new_chain = []
            for block_data in new_chain_data:
                block = Block(
                    block_data["index"],
                    block_data["transactions"],
                    block_data["previous_hash"]
                )
                block.timestamp = block_data["timestamp"]
                block.nonce = block_data["nonce"]
                block.merkle_root = block_data["merkle_root"]
                block.hash = block_data["hash"]
                new_chain.append(block)
            
            # Validate the new chain
            if len(new_chain) > len(self.chain) and self.is_chain_valid(new_chain):
                # Update processed transaction IDs from the new chain
                self.processed_tx_ids.clear()
                for block in new_chain:
                    for tx in block.transactions:
                        if 'tx_id' in tx:
                            self.processed_tx_ids.add(tx['tx_id'])
                
                # Also add pending transactions
                for tx in self.transactions:
                    if 'tx_id' in tx:
                        self.processed_tx_ids.add(tx['tx_id'])
                        
                self.chain = new_chain
                print(f"Chain synchronized. New length: {len(self.chain)}")
                return True
            else:
                print("Received chain is not valid or not longer than current chain")
                return False
        except Exception as e:
            print(f"Error syncing chain: {e}")
            return False
    
    def add_transaction(self, transaction, broadcast=True):
        if 'tx_id' not in transaction:
            transaction['tx_id'] = str(uuid.uuid4())
        
        # Check if we've already processed this transaction
        if transaction['tx_id'] in self.processed_tx_ids:
            print(f"Transaction {transaction['tx_id'][:8]} already processed, ignoring")
            return False
        
        # Add to processed set to prevent future duplicates
        self.processed_tx_ids.add(transaction['tx_id'])
        
        self.transactions.append(transaction)
        print(f"Transaction added: {transaction}")
        
        if broadcast:
            for peer in self.peers:
                try:
                    host, port = peer.split(':')
                    broadcast_transaction(transaction, host, int(port))
                except Exception as e:
                    print(f"Failed to broadcast transaction to {peer}: {e}")
        
        return True

def broadcast_transaction(transaction, host, port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, int(port)))
        request = json.dumps({
            "type": "ADD_TRANSACTION",
            "transaction": transaction
        }).encode()
        client.send(request)
        client.close()
        print(f"Transaction broadcasted to {host}:{port}")
    except Exception as e:
        print(f"Failed to broadcast to {host}:{port}: {e}")

def request_chain(host, port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, int(port)))
        request = json.dumps({"type": "GET_CHAIN"}).encode()
        client.send(request)
        response = client.recv(65536).decode()  # Increased buffer size
        client.close()
        return json.loads(response)
    except Exception as e:
        print(f"Failed to sync chain from {host}:{port}: {e}")
        return None

def start_peer_server(blockchain, host="0.0.0.0", port=5000):  
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
    try:
        server.bind((host, port))
        server.listen(5)
        print(f"Listening for peers on {host}:{port}")
        
        def handle_client(client_socket, client_address):
            try:
                request = client_socket.recv(4096).decode()
                data = json.loads(request)
                
                if data["type"] == "GET_CHAIN":
                    # Convert chain to serializable format
                    serialized_chain = []
                    for block in blockchain.chain:
                        serialized_chain.append(block.__dict__)
                    response = json.dumps(serialized_chain).encode()
                    client_socket.send(response)
                    print(f"Chain sent to {client_address}")
                elif data["type"] == "ADD_TRANSACTION":
                    # Pass broadcast=False to avoid forwarding again and creating a loop
                    blockchain.add_transaction(data["transaction"], broadcast=False)
                elif data["type"] == "ADD_PEER":
                    blockchain.add_peer(data["peer"])
                    print(f"Added peer from {client_address}")
            except Exception as e:
                print(f"Error handling client {client_address}: {e}")
            finally:
                client_socket.close()
        
        def server_loop():
            while True:
                try:
                    client, address = server.accept()
                    client_address = f"{address[0]}:{address[1]}"
                    print(f"Connection from {client_address}")
                    threading.Thread(target=handle_client, args=(client, client_address)).start()
                except Exception as e:
                    print(f"Server error: {e}")
                    break
        
        server_thread = threading.Thread(target=server_loop, daemon=True)
        server_thread.start()
        return server_thread, server
    except Exception as e:
        print(f"Failed to start server: {e}")
        server.close()
        return None, None

def broadcast_peer(peer_address, host, port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, int(port)))
        request = json.dumps({
            "type": "ADD_PEER",
            "peer": peer_address
        }).encode()
        client.send(request)
        client.close()
    except Exception as e:
        print(f"Failed to broadcast peer to {host}:{port}: {e}")

def menu(blockchain, my_address):
    while True:
        print("\n===== BLOCKCHAIN MENU =====")
        print("1. View Blockchain")
        print("2. Add Transaction")
        print("3. Mine Block")
        print("4. Add Peer")
        print("5. View Peers")
        print("6. Sync Blockchain from Peer")
        print("7. Validate Blockchain")
        print("8. Exit")
        choice = input("Enter choice: ")
        
        if choice == "1":
            if not blockchain.chain:
                print("Blockchain is empty")
            else:
                for i, block in enumerate(blockchain.chain):
                    print(f"\n----- Block {i} -----")
                    print(f"Timestamp: {time.ctime(block.timestamp)}")
                    print(f"Previous Hash: {block.previous_hash}")
                    print(f"Hash: {block.hash}")
                    print(f"Nonce: {block.nonce}")
                    print(f"Merkle Root: {block.merkle_root}")
                    print(f"Transactions ({len(block.transactions)}):")
                    for tx in block.transactions:
                        print(f"  {tx}")
        elif choice == "2":
            sender, _ = generate_bitcoin_address()
            receiver, _ = generate_bitcoin_address()
            try:
                amount = float(input("Enter amount: "))
                transaction = {
                    "sender": sender, 
                    "receiver": receiver, 
                    "amount": amount, 
                    "timestamp": time.time(),
                    "tx_id": str(uuid.uuid4())  
                }
                blockchain.add_transaction(transaction)
            except ValueError:
                print("Invalid amount. Please enter a number.")
        elif choice == "3":
            if not blockchain.transactions:
                print("No pending transactions to mine")
            else:
                new_block = blockchain.add_block()
                print(f"Block {new_block.index} mined successfully!")
                
                # Broadcast new block to peers by broadcasting the entire chain
                for peer in blockchain.peers:
                    try:
                        host, port = peer.split(':')
                        result = request_chain(host, int(port))
                        if result:
                            print(f"Successfully broadcasted new block to {peer}")
                    except Exception as e:
                        print(f"Failed to broadcast new block to {peer}: {e}")
        elif choice == "4":
            peer_host = input("Enter peer host: ")
            peer_port = input("Enter peer port: ")
            try:
                peer_address = f"{peer_host}:{peer_port}"
                blockchain.add_peer(peer_address)
                
                broadcast_peer(my_address, peer_host, int(peer_port))
            except Exception as e:
                print(f"Error adding peer: {e}")
        elif choice == "5":
            if not blockchain.peers:
                print("No peers connected")
            else:
                print("Connected peers:")
                for peer in blockchain.peers:
                    print(f"  {peer}")
        elif choice == "6":
            if not blockchain.peers:
                print("No peers available for sync")
            else:
                print("Available peers:")
                peers_list = list(blockchain.peers)
                for i, peer in enumerate(peers_list):
                    print(f"{i+1}. {peer}")
                try:
                    peer_idx = int(input("Select peer to sync from (number): ")) - 1
                    if 0 <= peer_idx < len(peers_list):
                        peer = peers_list[peer_idx]
                        host, port = peer.split(':')
                        new_chain = request_chain(host, int(port))
                        if new_chain:
                            if blockchain.sync_chain(new_chain):
                                print("Chain synchronized successfully")
                            else:
                                print("Failed to sync chain: validation failed")
                        else:
                            print("Failed to retrieve chain from peer")
                    else:
                        print("Invalid peer selection")
                except (ValueError, IndexError) as e:
                    print(f"Error selecting peer: {e}")
        elif choice == "7":
            if blockchain.is_chain_valid():
                print("Blockchain is valid!")
            else:
                print("Blockchain validation failed!")
        elif choice == "8":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
        host = "0.0.0.0"  # Listen on all interfaces
        if len(sys.argv) > 1:
            port = int(sys.argv[1])
        else:
            port = int(input("Enter port to listen on: "))
        
        my_address = f"{socket.gethostbyname(socket.gethostname())}:{port}"
        print(f"Your node address: {my_address}")
        
        blockchain = Blockchain()
        server_thread, server = start_peer_server(blockchain, host=host, port=port)
        if server_thread is None:
            print("Failed to start server. Exiting.")
            sys.exit(1)
            
        try:
            menu(blockchain, my_address)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            if server:
                server.close()
                print("Server closed")
    except Exception as e:
        print(f"Fatal error: {e}")