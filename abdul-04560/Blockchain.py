# This code contains the code for Assignment 3 where we have to create a blockchain and simulate it
# It will have a block class and a blockchain class, there will also be functions for computing
# merkle root, genesis block, latest block, valid block and adding a block

import hashlib
import time
from typing import List

# Hashlib is used for hashing the data
# time is used to get current time for the block to add
# List is used for the merkle root

def sha256(data): 
    return hashlib.sha256(data.encode()).hexdigest()

# The above function calculates the sha256 hash for any data passed

def merkle_root(transactions: List[str]) -> str:
    if not transactions:
        return ""
    
    transactions_hashes = [sha256(tx) for tx in transactions]

    while len(transactions_hashes) > 1:
        if len(transactions_hashes) % 2 != 0:
            transactions_hashes.append(transactions_hashes[-1])
        # The code above checks if there is any odd no of transactions, in that case we 
        # duplicate a transaction to make it even

        new_hashes = []
        for i in range (0, len(transactions_hashes), 2):
            combined_hashes = transactions_hashes[i] + transactions_hashes[i+1]
            new_hashes.append(sha256(combined_hashes))
        transactions_hashes = new_hashes

        # The return statement below gives the merkle root which is the last hash left
    return transactions_hashes[0]

# The code below defines the block class

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root(transactions)
        self.nonce = 0
        self.hash = self.hash_calculate()

    def hash_calculate(self):
        block_string = f"{self.index}{self.timestamp}{self.merkle_root}{self.previous_hash}{self.nonce}"
        return sha256(block_string)    
    # The method above calculates the block hash by adding all the strings together in a specific order and then hashing it

    def mine_block(self, difficulty):
        # following the proof of work methodoloy right now
        target = "0"* difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.hash_calculate()
        print(f"Block mined: {self.hash}")

    # The mine block function just sets a target for difficulty, then increases the nonce one by one and calulates the hash, 
    # it does it recursively until it gets a valid nonce that generates the hash, then it prints that

class Blockchain:
    def __init__(self, difficulty = 2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
    
    def create_genesis_block(self):
        return Block(0, time.time(), ["Genesis block"], "0")
    
    # The genesis block contains just the first block with everything set to 0

    def get_latest_block(self):
        return self.chain[-1]
    # returns the latest block from the chain

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
    # To add a block we need the previous blocks hash i.e. the block before the one we trying to append,call the mine_block function 
    # and append the new block to the chain 


    def is_chain_valid(self):
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block.hash_calculate():
                print("Invalid block")
                return False
            # It calculates the current blocks hash by calculating the hash    


            if current_block.previous_hash != previous_block.hash:
                print("Invalid block")
                return False
            # It checks the current blocks previous hash with the previous blocks hash


            if current_block.merkle_root != merkle_root(current_block.transactions):
                print("Invalid merkle root")
                return False
            # It checks the merkle root of the current block


        return True

blockchain = Blockchain()

blockchain.add_block(Block(1, time.time(), ["Alice sends 1 BTC to Bob", "Bob sends 0.75 BTC to Karen"], ""))
blockchain.add_block(Block(2, time.time(), ["Charlie sends 0.1 BTC to Alice", "Vlad sends 0.05 BTC to Karen"], ""))
blockchain.add_block(Block(3, time.time(), ["Vlad sends 0.01 BTC to Bob", "Alice sends 0.4 BTC to Vlad"], ""))

# Testing the add block functions

print("Is this Blockchain valid?", blockchain.is_chain_valid())


for block in blockchain.chain:
    print(f"Block {block.index} [Hash: {block.hash}, Previous Hash: {block.previous_hash}, Merkle Root: {block.merkle_root}, Transactions: {block.transactions}]")