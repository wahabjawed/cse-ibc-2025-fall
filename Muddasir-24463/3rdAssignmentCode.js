const crypto = require('crypto');

// Helper function to generate key pairs
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
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
    this.address = this.generateAddress();
  }

  generateAddress() {
    return crypto.createHash('sha256').update(this.publicKey).digest('hex');
  }

  signTransaction(transactionData) {
    const sign = crypto.createSign('SHA256');
    sign.update(transactionData);
    return sign.sign(this.privateKey, 'base64');
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
    this.inputs = inputs;   // Array of { txId, outputIndex, fromAddress, signature, publicKey }
    this.outputs = outputs; // Array of { toAddress, amount }
    this.id = this.calculateId();
  }

  calculateId() {
    return crypto.createHash('sha256').update(JSON.stringify(this.inputs) + JSON.stringify(this.outputs)).digest('hex');
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
    this.mempool = [];  // Mempool for pending transactions
    this.utxoSet = {}; // UTXO set (txId:outputIndex -> {toAddress, amount})
  }


  createGenesisBlock() {
    const genesisTx1 = new Transaction([], [{ toAddress: 'genesis1', amount: 30 }]);
    const genesisTx2 = new Transaction([], [{ toAddress: 'genesis2', amount: 40 }]);
    const genesisTx3 = new Transaction([], [{ toAddress: 'genesis3', amount: 30 }]);

    // Update UTXO set with genesis transactions
    this.updateUtxoSet(genesisTx1);
    this.updateUtxoSet(genesisTx2);
    this.updateUtxoSet(genesisTx3);
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


     // 1. Verify Signatures
    for (const input of transaction.inputs) {
        const txData = JSON.stringify({ from: input.fromAddress, amount: this.utxoSet[`${input.txId}:${input.outputIndex}`]?.amount }); // Construct data for signature verification
      if (!sender.verifySignature(txData, input.signature, input.publicKey)) {
        console.error('Invalid signature!');
        return; // Or throw an error
      }
    }

    // 2. Check if inputs are in UTXO set (and unspent)
    let totalInputValue = 0;
    for (const input of transaction.inputs) {
      const utxoKey = `${input.txId}:${input.outputIndex}`;
      if (!this.utxoSet[utxoKey]) {
        console.error(`Input UTXO not found: ${utxoKey}`);
        return; // Or throw an error
      }
      if(this.utxoSet[utxoKey].toAddress !== input.fromAddress){
        console.error(`Invalid address for utxo`);
        return
      }
      totalInputValue += this.utxoSet[utxoKey].amount;
    }

    // 3. Check if input amount >= output amount
    let totalOutputValue = 0;
    for (const output of transaction.outputs) {
      totalOutputValue += output.amount;
    }
    if (totalInputValue < totalOutputValue) {
      console.error('Insufficient input value');
      return;  // Or throw an error
    }

    this.mempool.push(transaction);
    return this.mempool.length; // Return mempool size (or transaction ID, etc.)
  }



  minePendingTransactions() {
      // Select transactions from the mempool
    const transactionsToMine = this.mempool.splice(0, 10); // Limit to 10 transactions
    const block = new Block(
        this.getLatestBlock().index + 1,
        new Date().toISOString(),
        transactionsToMine,
        this.getLatestBlock().hash
    );

    block.mineBlock(this.difficulty);
    console.log('Block successfully mined!');
    this.chain.push(block);

    // Update UTXO set *after* adding the block
    for (const tx of transactionsToMine) {
        this.updateUtxoSet(tx);
    }

    return block;
}

  updateUtxoSet(transaction) {
    // Remove spent UTXOs
    for (const input of transaction.inputs) {
      const utxoKey = `${input.txId}:${input.outputIndex}`;
      delete this.utxoSet[utxoKey];
    }

    // Add new UTXOs
    for (let i = 0; i < transaction.outputs.length; i++) {
      const utxoKey = `${transaction.id}:${i}`;
      this.utxoSet[utxoKey] = {
        toAddress: transaction.outputs[i].toAddress,
        amount: transaction.outputs[i].amount,
      };
    }
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
    const charlie = new User('Charlie');

    console.log('\nAdding transactions to mempool...');

    // --- Initial transactions from genesis block ---
    // We have genesis outputs at:
    // genesis1: 30  (txId: genesisTx1, outputIndex: 0)
    // genesis2: 40  (txId: genesisTx2, outputIndex: 0)
    // genesis3: 30  (txId: genesisTx3, outputIndex: 0)

    // --- Transaction 1:  genesis1 (30) -> Alice (20), genesis1 (10) ---
    const genesisTx1 = blockchain.chain[0].transactions[0]; // Get the actual genesis transaction
    const tx1Data = JSON.stringify({ from: 'genesis1', amount: 30 });  //Data to be signed.
    const tx1Signature = (new User('genesisUser')).signTransaction(tx1Data); //A dummy user is used for signature, as genesi block does not have a user.

    const tx1 = new Transaction(
        [{ txId: genesisTx1.id, outputIndex: 0, fromAddress: 'genesis1', signature: tx1Signature, publicKey: (new User('genesisUser')).publicKey}], // Input: genesis output
        [{ toAddress: alice.address, amount: 20 }, { toAddress: 'genesis1', amount: 10 }]         // Outputs: 20 to Alice, 10 change back to genesis1
    );
    blockchain.addTransactionToMempool(tx1, new User('genesisUser'));  // Use dummyUser for signature check

    // --- Transaction 2:  genesis2 (40) -> Bob (30), genesis2 (10)  ---

    const genesisTx2 = blockchain.chain[0].transactions[1];
    const tx2Data = JSON.stringify({ from: 'genesis2', amount: 40 });  //Data to be signed.
    const tx2Signature = (new User('genesisUser')).signTransaction(tx2Data);

    const tx2 = new Transaction(
      [{ txId: genesisTx2.id, outputIndex: 0, fromAddress: 'genesis2', signature: tx2Signature, publicKey: (new User('genesisUser')).publicKey }], // Input: genesis output
      [{ toAddress: bob.address, amount: 30 }, { toAddress: 'genesis2', amount: 10 }]
    );
    blockchain.addTransactionToMempool(tx2, new User('genesisUser'));


    console.log('Mining block 1 (from mempool)...');
    blockchain.minePendingTransactions();  // Mines tx1 and tx2


    // --- Transaction 3:  Alice (20) -> Charlie (15), Alice (5)  ---
    const tx3Data = JSON.stringify({from: alice.address, amount: 20})
    const tx3Signature = alice.signTransaction(tx3Data);
    const tx3 = new Transaction(
      [{ txId: tx1.id, outputIndex: 0, fromAddress: alice.address, signature: tx3Signature, publicKey: alice.publicKey }], // Input: tx1 output to alice
      [{ toAddress: charlie.address, amount: 15 }, { toAddress: alice.address, amount: 5 }] //output
    );
    blockchain.addTransactionToMempool(tx3, alice);


    // --- Transaction 4: Bob(30) -> Alice(30) ---
    const tx4Data = JSON.stringify({from: bob.address, amount: 30});
    const tx4Signature = bob.signTransaction(tx4Data);
    const tx4 = new Transaction(
        [{ txId: tx2.id, outputIndex: 0, fromAddress: bob.address, signature: tx4Signature, publicKey: bob.publicKey}],
        [{toAddress: alice.address, amount: 30}]
    );
    blockchain.addTransactionToMempool(tx4, bob);


    console.log('Mining block 2 (from mempool)...');
    blockchain.minePendingTransactions(); // Mines tx3 and tx4



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

    console.log("\nUTXO Set:");
    console.log(JSON.stringify(blockchain.utxoSet, null, 2));
}

main();