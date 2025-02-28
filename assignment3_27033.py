import hashlib
import json
from datetime import datetime

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce, hash):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash

class Blockchain:
    def __init__(self):
        self.chain = []
        self.difficulty = 4  # Number of leading zeros required for proof of work
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_transactions = ["Genesis Block"]
        genesis_timestamp = datetime.now().isoformat()
        genesis_previous_hash = "0"
        genesis_nonce, genesis_hash = self.proof_of_work(0, genesis_timestamp, genesis_transactions, genesis_previous_hash)
        genesis_block = Block(
            index=0,
            timestamp=genesis_timestamp,
            transactions=genesis_transactions,
            previous_hash=genesis_previous_hash,
            nonce=genesis_nonce,
            hash=genesis_hash
        )
        self.chain.append(genesis_block)

    @staticmethod
    def compute_hash(index, timestamp, transactions, previous_hash, nonce):
        block_data = {
            'index': index,
            'timestamp': timestamp,
            'transactions': transactions,
            'previous_hash': previous_hash,
            'nonce': nonce
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, index, timestamp, transactions, previous_hash):
        nonce = 0
        while True:
            hash_attempt = Blockchain.compute_hash(index, timestamp, transactions, previous_hash, nonce)
            if hash_attempt.startswith('0' * self.difficulty):
                return nonce, hash_attempt
            nonce += 1

    def add_block(self, transactions):
        previous_block = self.chain[-1]
        new_index = previous_block.index + 1
        new_timestamp = datetime.now().isoformat()
        previous_hash = previous_block.hash
        nonce, new_hash = self.proof_of_work(new_index, new_timestamp, transactions, previous_hash)
        new_block = Block(
            index=new_index,
            timestamp=new_timestamp,
            transactions=transactions,
            previous_hash=previous_hash,
            nonce=nonce,
            hash=new_hash
        )
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.previous_hash != previous_block.hash:
                return False

            computed_hash = Blockchain.compute_hash(
                current_block.index,
                current_block.timestamp,
                current_block.transactions,
                current_block.previous_hash,
                current_block.nonce
            )
            if current_block.hash != computed_hash:
                return False

            if not current_block.hash.startswith('0' * self.difficulty):
                return False

        return True

# Simulation
blockchain = Blockchain()

blockchain.add_block(["hammad sends 5 BTC to isht", "isht sends 2.5 BTC to musab"])
blockchain.add_block(["sire sends 1 BTC to king"])
blockchain.add_block(["queen sends 0.5 BTC to prince"])

print("Blockchain valid:", blockchain.is_chain_valid())

for block in blockchain.chain:
    print(f"Block {block.index}:")
    print(f"Timestamp: {block.timestamp}")
    print(f"Transactions: {block.transactions}")
    print(f"Previous Hash: {block.previous_hash}")
    print(f"Nonce: {block.nonce}")
    print(f"Hash: {block.hash}")
    print()