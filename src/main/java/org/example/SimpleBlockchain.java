package org.example;
import java.security.*;
import java.util.*;


class User {
    public String walletAddress;
    public PrivateKey privateKey;
    public PublicKey publicKey;

    public User() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            this.walletAddress = Blockchain.applySHA256(publicKey.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] signTransaction(String data) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(data.getBytes());
            return rsa.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verifySignature(PublicKey publicKey, String data, byte[] signature) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(publicKey);
            rsa.update(data.getBytes());
            return rsa.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Token {
    public String transactionId;
    public String owner;
    public double amount;
    public byte[] signature;
    public PublicKey publicKey;

    public Token(String transactionId, String owner, double amount, byte[] signature, PublicKey publicKey) {
        this.transactionId = transactionId;
        this.owner = owner;
        this.amount = amount;
        this.signature = signature;
        this.publicKey = publicKey;
    }
}

class Block {
    public int index;
    public long timestamp;
    public String previousHash;
    public String hash;
    public String merkleRoot;
    public int nonce;
    public List<Token> transactions;
    public int height;

    public Block(int index, String previousHash, List<Token> transactions, int height) {
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
    private List<Token> tokenPool;
    private int difficulty;

    public Blockchain(int difficulty) {
        this.difficulty = difficulty;
        chain = new ArrayList<>();
        tokenPool = new ArrayList<>();
        chain.add(createGenesisBlock());
    }

    private Block createGenesisBlock() {
        List<Token> genesisTokens = Arrays.asList(
                new Token("tx1", "A", 10, null, null),
                new Token("tx2", "B", 30, null, null),
                new Token("tx3", "C", 20, null, null)
        );
        tokenPool.addAll(genesisTokens);
        return new Block(0, "0", genesisTokens, 0);
    }

    public boolean addTransaction(Token transaction) {
        for (Token t : tokenPool) {
            if (t.transactionId.equals(transaction.transactionId)) {
                System.out.println("Double spending detected!");
                return false;
            }
        }
        if (!User.verifySignature(transaction.publicKey, transaction.transactionId, transaction.signature)) {
            System.out.println("Invalid transaction signature!");
            return false;
        }
        tokenPool.add(transaction);
        return true;
    }

    public void mineNewBlock() {
        if (tokenPool.isEmpty()) {
            System.out.println("No transactions to mine.");
            return;
        }
        Block newBlock = new Block(chain.size(), chain.get(chain.size() - 1).hash, new ArrayList<>(tokenPool), chain.size());
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);
        tokenPool.clear();
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
    public static String getMerkleRoot(List<Token> transactions) {
        if (transactions.isEmpty()) return "";
        List<String> temp = new ArrayList<>();
        for (Token t : transactions) {
            temp.add(t.transactionId);
        }
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
        User userA = new User();
        User userB = new User();
        User userC = new User();

        Token tx1 = new Token("tx4", "B", 10, userB.signTransaction("tx4"), userB.publicKey);
        blockchain.addTransaction(tx1);
        blockchain.mineNewBlock();

        Token tx2 = new Token("tx5", "C", 5, userB.signTransaction("tx5"), userB.publicKey);
        blockchain.addTransaction(tx2);
        blockchain.mineNewBlock();

        System.out.println("Blockchain valid: " + blockchain.isChainValid());
    }
}
