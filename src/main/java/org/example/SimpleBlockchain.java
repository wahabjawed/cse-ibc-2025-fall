package org.example;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

class Block {
    public int index;
    public long timestamp;
    public String previousHash;
    public String hash;
    public String merkleRoot;
    public int nonce;
    public List<String> transactions;
    public int height;

    public Block(int index, String previousHash, List<String> transactions, int height) {
        this.index = index;
        this.timestamp = new Date().getTime();
        this.previousHash = previousHash;
        this.transactions = new ArrayList<>(transactions);
        this.merkleRoot = MerkleTree.getMerkleRoot(transactions);
        this.hash = calculateHash();
        this.height = height;
    }

    public String calculateHash() {
        return Blockchain.applySHA256(index + timestamp + previousHash + merkleRoot + nonce + height);
    }

    public void mineBlock(int difficulty) {
        String target = new String(new char[difficulty]).replace('\0', '0');
        while (!hash.substring(0, difficulty).equals(target)) {
            nonce++;
            hash = calculateHash();
        }
        System.out.println("Block Mined: " + hash);
    }
}

class Blockchain {
    private List<Block> chain;
    private List<String> mempool;
    private int difficulty;

    public Blockchain(int difficulty) {
        this.difficulty = difficulty;
        chain = new ArrayList<>();
        mempool = new ArrayList<>();
        chain.add(createGenesisBlock());
    }

    private Block createGenesisBlock() {
        return new Block(0, "0", new ArrayList<>(), 0);
    }

    public void addTransaction(String transaction) {
        mempool.add(transaction);
    }

    public void mineNewBlock() {
        if (mempool.isEmpty()) {
            System.out.println("No transactions to mine.");
            return;
        }
        Block newBlock = new Block(chain.size(), chain.get(chain.size() - 1).hash, new ArrayList<>(mempool), chain.size());
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);
        mempool.clear();
    }

    public boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block current = chain.get(i);
            Block previous = chain.get(i - 1);
            if (!current.hash.equals(current.calculateHash()) || !current.previousHash.equals(previous.hash)) {
                return false;
            }
        }
        return true;
    }

    public static String applySHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class MerkleTree {
    public static String getMerkleRoot(List<String> transactions) {
        if (transactions.isEmpty()) return "";
        List<String> temp = new ArrayList<>(transactions);
        while (temp.size() > 1) {
            List<String> newHashList = new ArrayList<>();
            for (int i = 0; i < temp.size(); i += 2) {
                String combined = temp.get(i) + (i + 1 < temp.size() ? temp.get(i + 1) : "");
                newHashList.add(Blockchain.applySHA256(combined));
            }
            temp = newHashList;
        }
        return temp.get(0);
    }
}

public class SimpleBlockchain {
    public static void main(String[] args) {
        Blockchain blockchain = new Blockchain(2);

        blockchain.addTransaction("Alice pays Bob 10 BTC");
        blockchain.addTransaction("Bob pays Charlie 5 BTC");
        blockchain.mineNewBlock();

        blockchain.addTransaction("Charlie pays Dave 2 BTC");
        blockchain.mineNewBlock();

        blockchain.addTransaction("Dave pays Alice 1 BTC");
        blockchain.mineNewBlock();

        System.out.println("Blockchain valid: " + blockchain.isChainValid());
    }
}

