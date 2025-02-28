const crypto = require('crypto');

class Block {
  constructor(index, timestamp, transactions, previousHash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.nonce = 0;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return crypto.createHash('sha256')
      .update(
        this.index +
        this.timestamp +
        JSON.stringify(this.transactions) +
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
    return new Block(0, new Date().toISOString(), ['Genesis Block'], '0');
  }
  
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }
  
  addTransaction(transaction) {
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
        return false;
      }
      
      // Validate chain link (previous hash reference)
      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
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
  blockchain.addTransaction({ from: 'Alice', to: 'Bob', amount: 50 });
  blockchain.addTransaction({ from: 'Bob', to: 'Charlie', amount: 25 });
  console.log('Mining block 1...');
  blockchain.minePendingTransactions();
  
  console.log('\nAdding more transactions...');
  blockchain.addTransaction({ from: 'Charlie', to: 'Dave', amount: 10 });
  blockchain.addTransaction({ from: 'Dave', to: 'Eve', amount: 5 });
  console.log('Mining block 2...');
  blockchain.minePendingTransactions();
  
  console.log('\nAdding final transactions...');
  blockchain.addTransaction({ from: 'Eve', to: 'Alice', amount: 15 });
  blockchain.addTransaction({ from: 'Alice', to: 'Charlie', amount: 20 });
  console.log('Mining block 3...');
  blockchain.minePendingTransactions();
  
  console.log('\nBlockchain validation:', blockchain.isChainValid() ? 'Valid' : 'Invalid');
  
  console.log('\nFull blockchain:');
  console.log(JSON.stringify(blockchain, null, 2));
}

main();