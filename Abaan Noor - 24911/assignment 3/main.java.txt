import java.util.ArrayList;
import java.util.List;
import java.util.Date;
import java.security.MessageDigest;

class Block {
    public int index;
    public long timestamp;
    public List<String> transactions;
    public String previousHash;
    public String hash;
    public int nonce;

    // Constructor
    public Block(int index, List<String> transactions, String previousHash) {
        this.index = index;
        this.timestamp = new Date().getTime();
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = calculateHash();
    }

    // Calculate the hash of the block
    public String calculateHash() {
        String dataToHash = index + timestamp + transactions.toString() + previousHash + nonce;
        return applySHA256(dataToHash);
    }

    // Mining function that ensures proof of work
    public void mineBlock(int difficulty) {
        long startTime = System.currentTimeMillis(); // Track mining start time

        String target = "0".repeat(difficulty); // Target hash pattern
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }

        long endTime = System.currentTimeMillis(); // Track mining end time
        System.out.println("✅ Block Mined! Hash: " + hash + " ⏳ Mining Time: " + (endTime - startTime) + "ms");
    }

    // Apply SHA-256 hashing algorithm
    public static String applySHA256(Strting input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Blockchain {
    private List<Block> chain;
    private int difficulty;

    // Constructor
    public Blockchain(int initialDifficulty) {
        this.chain = new ArrayList<>();
        this.difficulty = initialDifficulty;
        chain.add(createGenesisBlock()); // Create the first block in the blockchain
    }

    // Create the Genesis Block (first block in the blockchain)
    private Block createGenesisBlock() {
        List<String> genesisTransactions = new ArrayList<>();
        genesisTransactions.add("Genesis Block - First Block in the Chain");
        
        Block genesisBlock = new Block(0, genesisTransactions, "0");
        genesisBlock.mineBlock(difficulty); // Ensure it's also mined!
        
        return genesisBlock;
    }

    // Get the latest block in the blockchain
    public Block getLatestBlock() {
        return chain.get(chain.size() - 1);
    }

    // Add a new block to the blockchain
    public void addBlock(List<String> transactions) {
        long previousTime = System.currentTimeMillis(); // Start timing

        Block newBlock = new Block(chain.size(), transactions, getLatestBlock().hash);
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);

        long newTime = System.currentTimeMillis(); // End timing
        adjustDifficulty(previousTime, newTime); // Adjust mining difficulty dynamically
    }

    // Adjust mining difficulty based on block mining time
    public void adjustDifficulty(long previousTime, long newTime) {
        long miningTime = newTime - previousTime;

        if (miningTime < 500) {
            difficulty++;  // Increase difficulty if mining is too fast
        } else if (miningTime > 5000 && difficulty > 1) {
            difficulty--;  // Decrease difficulty if mining is too slow
        }

        System.out.println("⚙️ Difficulty adjusted to: " + difficulty);
    }

    // Validate the integrity of the blockchain
    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block currentBlock = chain.get(i);
            Block previousBlock = chain.get(i - 1);

            // Check if current block's hash is correct
            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                return false;
            }

            // Check if current block properly references the previous block
            if (!currentBlock.previousHash.equals(previousBlock.hash)) {
                return false;
            }
        }
        return true;
    }

    // Print blockchain details
    public void printBlockchain() {
        System.out.println("\n📜 Blockchain Details:\n");

        for (Block block : chain) {
            System.out.println("----------------------");
            System.out.println("Block #" + block.index);
            System.out.println("Timestamp: " + block.timestamp);
            System.out.println("Transactions: " + block.transactions);
            System.out.println("Previous Hash: " + block.previousHash);
            System.out.println("Hash: " + block.hash);
            System.out.println("Nonce: " + block.nonce);
            System.out.println("----------------------\n");
        }

        System.out.println("🔍 Blockchain Valid? " + isChainValid());
    }
}

public class Main {
    public static void main(String[] args) {
        Blockchain blockchain = new Blockchain(4); // Initial difficulty = 4

        // Adding blocks with dummy transactions
        System.out.println("🚀 Mining Block 1...");
        blockchain.addBlock(List.of("Alice pays Bob 10 BTC", "John buys 2 ETH"));

        System.out.println("🚀 Mining Block 2...");
        blockchain.addBlock(List.of("Bob pays Charlie 5 BTC", "Charlie sells NFT to Eve"));

        System.out.println("🚀 Mining Block 3...");
        blockchain.addBlock(List.of("Eve buys 1 BTC", "David stakes 20 ADA"));

        // Print full blockchain details
        blockchain.printBlockchain();
    }
}
