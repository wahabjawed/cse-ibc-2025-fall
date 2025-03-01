const crypto = require('crypto');

// Helper function to generate key pairs
function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Standard key length
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    return { publicKey, privateKey };
}

class User {
    constructor(name) {
        this.name = name;
        const { publicKey, privateKey } = generateKeyPair();
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.address = this.generateAddress(); // Generate address from public key
    }

    generateAddress() {
        // Simplified address generation (SHA-256 of public key)
        return crypto.createHash('sha256').update(this.publicKey).digest('hex');
    }

    signTransaction(transactionData) {
        const sign = crypto.createSign('SHA256');
        sign.update(transactionData);
        const signature = sign.sign(this.privateKey, 'base64'); // Sign with private key
        return signature;
    }

    verifySignature(transactionData, signature, publicKey) {
      try {
        const verify = crypto.createVerify('SHA256');
        verify.update(transactionData);
        return verify.verify(publicKey, signature, 'base64');
      } catch (error) {
        console.error("Signature verification error:", error);
        return false;
      }
    }
}

class MerkleTree {
    constructor(transactions) {
        this.transactions = transactions;
        this.root = this.buildTree(transactions);
    }

    buildTree(transactions) {
        if (transactions.length === 0) {
            return null;
        }

        if (transactions.length === 1) {
            return this.hashLeaf(transactions[0]);
        }

        const mid = Math.ceil(transactions.length / 2);
        const left = this.buildTree(transactions.slice(0, mid));
        const right = this.buildTree(transactions.slice(mid));
        return this.hashNode(left, right);
    }

    hashLeaf(transaction) {
        const transactionString = JSON.stringify(transaction);
        return crypto.createHash('sha256').update(transactionString).digest('hex');
    }

    hashNode(left, right) {
        return crypto.createHash('sha256').update(left + right).digest('hex');
    }

    getRoot() {
        return this.root;
    }

  verifyTransaction(transaction) {
    const transactionHash = this.hashLeaf(transaction);
    let currentLevel = this.transactions.map(tx => this.hashLeaf(tx));

    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : left; // Handle odd number of nodes
        const parentHash = this.hashNode(left, right);
        nextLevel.push(parentHash);
        if ((left === transactionHash || right === transactionHash) && nextLevel.includes(parentHash)) {
              return true; //early return
        }
      }
      currentLevel = nextLevel;
    }
    return currentLevel[0] === this.root; // Check if it reaches the root
  }
}

class Transaction {
    constructor(inputs, outputs) {
        this.inputs = inputs;   // Array of { fromAddress, amount, signature, publicKey }
        this.outputs = outputs; // Array of { toAddress, amount }
        this.id = this.calculateId();
    }

    calculateId() {
        return crypto.createHash('sha256')
            .update(JSON.stringify(this.inputs) + JSON.stringify(this.outputs))
            .digest('hex');
    }
}


class Block {
    constructor(index, timestamp, transactions, previousHash = '') {
        this.index = index;
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.merkleTree = new MerkleTree(transactions);
        this.merkleRoot = this.merkleTree.getRoot();
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return crypto.createHash('sha256')
            .update(
                this.index +
                this.timestamp +
                this.merkleRoot +
                this.previousHash +
                this.nonce
            )
            .digest('hex');
    }

    mineBlock(difficulty) {
        const target = Array(difficulty + 1).join('0');

        while (this.hash.substring(0, difficulty) !== target) {
            this.nonce++;
            this.hash = this.calculateHash();
        }

        console.log(`Block mined: ${this.hash}`);
    }
}


class Blockchain {
    constructor(difficulty = 4) {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = difficulty;
        this.mempool = []; // Mempool to store unconfirmed transactions
    }

    createGenesisBlock() {
      // Create multiple genesis transactions
      const genesisTx1 = new Transaction([], [{ toAddress: 'genesis1', amount: 30 }]);
      const genesisTx2 = new Transaction([], [{ toAddress: 'genesis2', amount: 40 }]);
      const genesisTx3 = new Transaction([], [{ toAddress: 'genesis3', amount: 30 }]);
      return new Block(0, new Date().toISOString(), [genesisTx1, genesisTx2, genesisTx3], '0');
  }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }


    addTransactionToMempool(transaction, sender) {
        if (!transaction.inputs || !transaction.outputs) {
            throw new Error('Transaction must include inputs and outputs');
        }
        if (!Array.isArray(transaction.inputs) || !Array.isArray(transaction.outputs)) {
          throw new Error("Inputs and outputs must be arrays.");
        }


        // Verify signatures for all inputs
        for (const input of transaction.inputs) {
          const txData = JSON.stringify({ from: input.fromAddress, amount: input.amount });
          if (!sender.verifySignature(txData, input.signature, input.publicKey)) { // Verify signature
            console.error('Invalid signature!');
            return; // Or throw an error
          }
        }
      
        this.mempool.push(transaction);
        return this.mempool.length;
    }
  
  minePendingTransactions() {
    // Select transactions from the mempool (simple FIFO in this example)
    const transactionsToMine = this.mempool.splice(0, 10); // Limit to 10 txs per block

    const block = new Block(
      this.getLatestBlock().index + 1,
      new Date().toISOString(),
      transactionsToMine,
      this.getLatestBlock().hash
    );

    block.mineBlock(this.difficulty);
    console.log('Block successfully mined!');
    this.chain.push(block);

    // No need to clear pendingTransactions; it's managed by splicing from mempool

    return block;
  }



    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                console.error(`Invalid hash at block ${i}`);
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash) {
                console.error(`Invalid previous hash at block ${i}`);
                return false;
            }

            const recalculatedMerkleRoot = new MerkleTree(currentBlock.transactions).getRoot();
            if (currentBlock.merkleRoot !== recalculatedMerkleRoot) {
                console.error(`Invalid Merkle root at block ${i}`);
                return false;
            }
            for (const tx of currentBlock.transactions) {
                if (!tx.inputs || !tx.outputs || !tx.id) {
                    console.error(`Invalid transaction format in block ${i}`);
                    return false;
                }
            }
        }

        return true;
    }
}

// Main execution
function main() {
    console.log('Creating a new blockchain...');
    const blockchain = new Blockchain();

        // Parse command line arguments for difficulty
  const args = process.argv.slice(2);
  if (args.length > 0) {
    const difficultyArg = args.find(arg => arg.startsWith('--difficulty='));
    if (difficultyArg) {
      const difficulty = parseInt(difficultyArg.split('=')[1]);
      if (!isNaN(difficulty)) {
        blockchain.difficulty = difficulty;
        console.log(`Setting mining difficulty to ${difficulty}`);
      }
    }
  }

    // Create users
    const alice = new User('Alice');
    const bob = new User('Bob');
    const charlie = new User("Charlie");

    console.log('\nAdding transactions to mempool...');

    // Create a transaction from Alice to Bob
    const tx1Data = JSON.stringify({ from: alice.address, amount: 50 });
    const tx1Signature = alice.signTransaction(tx1Data);

    const tx1 = new Transaction(
        [{ fromAddress: alice.address, amount: 50, signature: tx1Signature, publicKey: alice.publicKey }], //inputs
        [{ toAddress: bob.address, amount: 50 }] //outputs
    );
    blockchain.addTransactionToMempool(tx1, alice);  // Add to mempool


     // Create a transaction from Bob to Charlie
    const tx2Data = JSON.stringify({ from: bob.address, amount: 25 });
    const tx2Signature = bob.signTransaction(tx2Data);
    const tx2 = new Transaction(
        [{ fromAddress: bob.address, amount: 25, signature: tx2Signature, publicKey: bob.publicKey }], //inputs
        [{ toAddress: charlie.address, amount: 25 }] //outputs
    );

    blockchain.addTransactionToMempool(tx2, bob);


    console.log('Mining block 1 (from mempool)...');
    blockchain.minePendingTransactions();


    // Create a transaction from Charlie to Alice
    const tx3Data = JSON.stringify({ from: charlie.address, amount: 10 });
    const tx3Signature = charlie.signTransaction(tx3Data);

    const tx3 = new Transaction(
        [{ fromAddress: charlie.address, amount: 10, signature: tx3Signature, publicKey: charlie.publicKey }],
        [{ toAddress: alice.address, amount: 10 }]
    );
    blockchain.addTransactionToMempool(tx3, charlie);  // Add to mempool

    console.log('Mining block 2 (from mempool)...');
    blockchain.minePendingTransactions();

    console.log('\nBlockchain validation:', blockchain.isChainValid() ? 'Valid' : 'Invalid');
     console.log(`Verifying tx1 in blockchain: ${blockchain.chain[1].merkleTree.verifyTransaction(tx1)}`);
    console.log('\nFull blockchain:');
    console.log(JSON.stringify(blockchain, null, 2));

    console.log("\nUsers:");
    console.log("Alice:", { address: alice.address, publicKey: alice.publicKey });
    console.log("Bob:", { address: bob.address, publicKey: bob.publicKey });
     console.log("Charlie:", { address: charlie.address, publicKey: charlie.publicKey});


    console.log("\nMempool:");
    console.log(JSON.stringify(blockchain.mempool, null, 2));
}

main();