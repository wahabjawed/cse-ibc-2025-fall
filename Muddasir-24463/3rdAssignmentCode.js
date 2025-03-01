const crypto = require('crypto');

class MerkleTree {
  constructor(transactions) {
    this.transactions = transactions;
    this.root = this.buildTree(transactions);
  }

  buildTree(transactions) {
    if (transactions.length === 0) {
      return null; // Handle empty transaction list (important!)
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
    const transactionString = JSON.stringify(transaction); // Stringify the transaction
    return crypto.createHash('sha256').update(transactionString).digest('hex');
  }

  hashNode(left, right) {
    return crypto.createHash('sha256').update(left + right).digest('hex');
  }

  getRoot() {
    return this.root;
  }

  // Optional:  Method to verify if a transaction is included in the tree
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
    this.inputs = inputs;   // Array of { from, amount, signature } objects
    this.outputs = outputs; // Array of { to, amount } objects
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
    this.transactions = transactions;  // Array of Transaction objects
    this.previousHash = previousHash;
    this.nonce = 0;
    this.merkleTree = new MerkleTree(transactions);
    this.merkleRoot = this.merkleTree.getRoot(); // Store the Merkle root
    this.hash = this.calculateHash();
  }

  calculateHash() {
      return crypto.createHash('sha256')
          .update(
              this.index +
              this.timestamp +
              this.merkleRoot + // Use the Merkle root in the block hash
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
    this.pendingTransactions = [];
  }

  createGenesisBlock() {
    const genesisTx = new Transaction([], [{ to: 'genesis', amount: 100 }]);
    return new Block(0, new Date().toISOString(), [genesisTx], '0');
  }


  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addTransaction(transaction) {
    if (!transaction.inputs || !transaction.outputs) {
      throw new Error('Transaction must include inputs and outputs');
    }
    //  Basic validation (you would add more robust validation here)
    if (!Array.isArray(transaction.inputs) || !Array.isArray(transaction.outputs))
    {
        throw new Error("Inputs and outputs must be arrays.");
    }

    this.pendingTransactions.push(transaction);
    return this.getLatestBlock().index + 1;
  }


  minePendingTransactions() {
    const block = new Block(
      this.getLatestBlock().index + 1,
      new Date().toISOString(),
      this.pendingTransactions,
      this.getLatestBlock().hash
    );

    block.mineBlock(this.difficulty);

    console.log('Block successfully mined!');
    this.chain.push(block);

    this.pendingTransactions = [];

    return block;
  }

  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      // Validate current block's hash
      if (currentBlock.hash !== currentBlock.calculateHash()) {
        console.error(`Invalid hash at block ${i}`);
        return false;
      }

      // Validate chain link (previous hash reference)
      if (currentBlock.previousHash !== previousBlock.hash) {
           console.error(`Invalid previous hash at block ${i}`);
        return false;
      }

      // Validate Merkle root
      const recalculatedMerkleRoot = new MerkleTree(currentBlock.transactions).getRoot();
      if (currentBlock.merkleRoot !== recalculatedMerkleRoot) {
        console.error(`Invalid Merkle root at block ${i}`);
        return false;
      }

       //Validate transactions
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

  console.log('\nAdding transactions...');
  const tx1 = new Transaction(
    [{ from: 'Alice', amount: 100, signature: 'signature1' }], // Example inputs
    [{ to: 'Bob', amount: 50 }, { to: 'Alice', amount: 50 }] // Example outputs
  );
  blockchain.addTransaction(tx1);

  const tx2 = new Transaction(
    [{ from: 'Bob', amount: 50, signature: 'signature2' }],
    [{ to: 'Charlie', amount: 25 }, { to: 'Bob', amount: 25 }]
  );
    blockchain.addTransaction(tx2);

  console.log('Mining block 1...');
  blockchain.minePendingTransactions();

  console.log('\nAdding more transactions...');
  const tx3 = new Transaction(
    [{ from: 'Charlie', amount: 25, signature: 'signature3' }],
    [{ to: 'Dave', amount: 10 }, {to: 'Charlie', amount: 15}]
  );
    blockchain.addTransaction(tx3);

  const tx4 = new Transaction(
    [{ from: 'Dave', amount: 10, signature: 'signature4' }],
    [{ to: 'Eve', amount: 5 }, {to: 'Dave', amount: 5}]
  );
    blockchain.addTransaction(tx4);
  console.log('Mining block 2...');
  blockchain.minePendingTransactions();

  console.log('\nAdding final transactions...');
    const tx5 = new Transaction(
    [{ from: 'Eve', amount: 5, signature: 'signature4' }],
    [{ to: 'Alice', amount: 5 }, {to: 'Eve', amount: 0}]
  );
  blockchain.addTransaction(tx5);

  const tx6 = new Transaction(
      [{ from: 'Alice', amount: 5, signature: 'signature4' }],
      [{ to: 'Bob', amount: 5 }]
  );
  blockchain.addTransaction(tx6);
  console.log('Mining block 3...');
  blockchain.minePendingTransactions();

  console.log('\nBlockchain validation:', blockchain.isChainValid() ? 'Valid' : 'Invalid');
    console.log(`Verifying tx1 in blockchain: ${blockchain.chain[1].merkleTree.verifyTransaction(tx1)}`);
  console.log('\nFull blockchain:');
  console.log(JSON.stringify(blockchain, null, 2));
}

main();