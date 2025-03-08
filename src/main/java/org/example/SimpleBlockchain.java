package org.example;
import java.security.*;
import java.util.*;


class Transaction {
    public String transactionId;
    public String owner;
    public List<Token> input = new ArrayList<>();
    public List<Token> output = new ArrayList<>();
    public byte[] signature;
    public PublicKey publicKey;

    public Transaction(String transactionId, String owner, List<Token> input, List<Token> output, byte[] signature, PublicKey publicKey) {
        this.transactionId = transactionId;
        this.owner = owner;
        this.input = input;
        this.output = output;
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
    public List<Transaction> transactions;
    public int height;

    public Block(int index, String previousHash, List<Transaction> transactions, int height) {
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
    private List<Block> chain = new ArrayList<>();
    private List<Token> UTXO = new ArrayList<Token>();
    private int difficulty=2;
    private List<Transaction> mempool = new ArrayList<>();


    private Block createGenesisBlock() {
        List<Transaction> genesisTransactions = Arrays.asList(
                new Transaction("tx1", "A", Collections.emptyList(), List.of(new Token("", 2)), null,null)
        );
        return new Block(0, "0", genesisTransactions, 0);
    }
    public Blockchain(){
       Block genesisBlock= createGenesisBlock();
       chain.add(genesisBlock);
       for(int i =0; i< genesisBlock.transactions.size(); i++){
       UTXO.addAll(genesisBlock.transactions.get(i).output);
       }

    }

    public List<Token> getUTXO() {
        return UTXO;
    }

    public boolean addTransaction(Transaction transaction) {
        for (Token t : transaction.input) {
            if (!UTXO.contains(t)) {
                System.out.println("Double spending detected!");
                return false;
            }
        }
        if (!User.verifySignature(transaction.publicKey, transaction.transactionId, transaction.signature)) {
            System.out.println("Invalid transaction signature!");
            return false;
        }
        mempool.add(transaction);
//        UTXO.addAll(transaction.output);
//        UTXO.removeAll(transaction.input);
        return true;
    }

    public void mineNewBlock() {
        if (mempool.isEmpty()) {
            System.out.println("No transactions to mine.");
            return;
        }
        Block newBlock = new Block(chain.size(), chain.get(chain.size() - 1).hash, new ArrayList<>(mempool), chain.size());
        newBlock.mineBlock(difficulty);
        chain.add(newBlock);
        for(int i=0; i<mempool.size();i++) {
            UTXO.addAll(mempool.get(i).output);
            UTXO.removeAll(mempool.get(i).input);
        }
        for(int i=0; i<UTXO.size();i++){
        System.out.println("Utxo at index "+i+" "+ UTXO.get(i).toString());}

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

    public List<Token> findTokens(PublicKey publicKey, int i) {
        List<Token> tokens = new ArrayList<>();
        for (int j = 0; j< mempool.size(); j++){
            if(publicKey==mempool.get(j).publicKey){
                tokens.addAll(mempool.get(j).input);
            }
        }
        return tokens;
    }
}

class MerkleTree {
    public static String getMerkleRoot(List<Transaction> transactions) {
        if (transactions.isEmpty()) return "";
        List<String> temp = new ArrayList<>();
        for (Transaction t : transactions) {
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
            Blockchain blockchain = new Blockchain();
            User userA = new User();
            User userB = new User();
            User userC = new User();

            List<Token> inputsA = new ArrayList<>(blockchain.getUTXO()); // Takes all available UTXOs
            List<Token> outputsA = List.of(new Token(userA.publicKey.toString(), 10),
                    new Token(userA.publicKey.toString(), 30),
                    new Token(userA.publicKey.toString(), 20)); // Splitting into 10, 30, 20

            Transaction txA = new Transaction("txA", "A", inputsA, outputsA,
                    userA.signTransaction("txA"), userA.publicKey);
            blockchain.addTransaction(txA);
            blockchain.mineNewBlock();

            List<Token> inputsB = blockchain.findTokens(userA.publicKey, 25);
            List<Token> outputsB = List.of(new Token(userB.publicKey.toString(), 25),
                    new Token(userA.publicKey.toString(), 5)); // A keeps change

            Transaction txB = new Transaction("txB", "B", inputsB, outputsB,
                    userA.signTransaction("txB"), userA.publicKey);
            blockchain.addTransaction(txB);
            blockchain.mineNewBlock();

            List<Token> inputsC = blockchain.findTokens(userB.publicKey, 20);
            List<Token> outputsC = List.of(new Token(userC.publicKey.toString(), 15),
                    new Token(userA.publicKey.toString(), 5)); // Miner fee

            Transaction txC = new Transaction("txC", "C", inputsC, outputsC,
                    userB.signTransaction("txC"), userB.publicKey);
            blockchain.addTransaction(txC);
            blockchain.mineNewBlock();

            // Validation
            System.out.println("Blockchain valid: " + blockchain.isChainValid());
        }
    }


