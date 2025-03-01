#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

string sha256(const string str) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, hash, &len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for(unsigned int i = 0; i < len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class KeyPair{
public:
    EVP_PKEY* privateKey = nullptr;
    EVP_PKEY* publicKey = nullptr;
    
    KeyPair() {
        // Generate the private key
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            cerr << "Error creating EVP_PKEY_CTX" << endl;
            return;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            cerr << "Error initializing keygen" << endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            cerr << "Error setting RSA keygen bits" << endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        if (EVP_PKEY_keygen(ctx, &privateKey) <= 0) {
            cerr << "Error generating key" << endl;
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        EVP_PKEY_CTX_free(ctx);
        
        // Duplicate the private key to create the public key
        publicKey = EVP_PKEY_dup(privateKey);
        if (!publicKey) {
            cerr << "Error duplicating privateKey to publicKey" << endl;
        }
    }
    
    ~KeyPair() {
        if(privateKey)
            EVP_PKEY_free(privateKey);
        if(publicKey)
            EVP_PKEY_free(publicKey);
    }
};

struct TXOutput {
    double amount;
    string recipient;
};

struct TXInput {
    string txId;
    int outputIndex;
    string signature;
};

class Transaction {
public:
    string txId;
    vector<TXInput> inputs;
    vector<TXOutput> outputs;
    time_t timestamp;

    Transaction(vector<TXInput> in, vector<TXOutput> out) 
        : inputs(in), outputs(out), timestamp(time(nullptr)) {
        calculateHash();
    }

    void calculateHash() {
        stringstream ss;
        ss << timestamp;
        for(auto& in : inputs) {
            ss << in.txId << in.outputIndex;
        }
        for(auto& out : outputs) {
            ss << out.amount << out.recipient;
        }
        txId = sha256(ss.str());
    }
};

class Block {
public:
    int index;
    time_t timestamp;
    vector<Transaction> transactions;
    string previousHash;
    string hash;
    int nonce;

    Block(int idx, vector<Transaction> txs, string prevHash)
        : index(idx), timestamp(time(nullptr)), 
          transactions(txs), previousHash(prevHash), nonce(0) {
        hash = calculateHash();
    }

    string calculateHash() const {
        stringstream ss;
        ss << index << timestamp << previousHash << nonce;
        for(auto& tx : transactions) {
            ss << tx.txId;
        }
        return sha256(ss.str());
    }

    void mineBlock(int difficulty) {
        string target(difficulty, '0');
        while(hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculateHash();
        }
    }
};

class Blockchain {
private:
    vector<Block> chain;
    int difficulty;
    vector<TXOutput> UTXO;

public:
    Blockchain() : difficulty(4) {
        createGenesisBlock();
    }

    void createGenesisBlock() {
        vector<Transaction> txs;
        KeyPair genesisKey;
        txs.emplace_back(vector<TXInput>{}, vector<TXOutput>{{100.0, "Genesis"}});
        Block genesis(0, txs, "0");
        genesis.mineBlock(difficulty);
        chain.push_back(genesis);
        
        UTXO.push_back({100.0, "Genesis"});
    }

    Block getLastBlock() const {
        return chain.back();
    }

    void addBlock(Block newBlock) {
        newBlock.previousHash = getLastBlock().hash;
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
        
        for(auto& tx : newBlock.transactions) {
            for(auto& output : tx.outputs) {
                UTXO.push_back(output);
            }
        }
    }

    bool isChainValid() {
        for(size_t i = 1; i < chain.size(); i++) {
            const Block& current = chain[i];
            const Block& previous = chain[i-1];

            if(current.hash != current.calculateHash()) {
                cout << "Invalid hash at block " << i << endl;
                return false;
            }

            if(current.previousHash != previous.hash) {
                cout << "Invalid previous hash at block " << i << endl;
                return false;
            }

            if(current.hash.substr(0, difficulty) != string(difficulty, '0')) {
                cout << "Block " << i << " not mined properly" << endl;
                return false;
            }
        }
        return true;
    }

    void printUTXO() {
        cout << "\nUTXO Set:" << endl;
        for(size_t i = 0; i < UTXO.size(); i++) {
            cout << "UTXO " << i << ": " << UTXO[i].amount 
                 << " to " << UTXO[i].recipient << endl;
        }
    }
};

int main() {
    Blockchain bc;

    KeyPair minerKey, aliceKey, bobKey;

    vector<Transaction> txs1;
    txs1.emplace_back(vector<TXInput>{}, vector<TXOutput>{{50.0, "Miner"}});
    Block block1(1, txs1, bc.getLastBlock().hash);
    bc.addBlock(block1);

    vector<Transaction> txs2;
    TXInput in1{"genesis_tx_id", 0, "sig"};
    TXOutput out1{30.0, "Alice"}, out2{20.0, "Miner"};
    txs2.emplace_back(vector<TXInput>{in1}, vector<TXOutput>{out1, out2});
    Block block2(2, txs2, bc.getLastBlock().hash);
    bc.addBlock(block2);

    vector<Transaction> txs3;
    TXInput in2{"tx2_id", 0, "sig"};
    TXOutput out3{15.0, "Bob"}, out4{15.0, "Alice"};
    txs3.emplace_back(vector<TXInput>{in2}, vector<TXOutput>{out3, out4});
    Block block3(3, txs3, bc.getLastBlock().hash);
    bc.addBlock(block3);

    cout << "Blockchain valid: " << (bc.isChainValid() ? "Yes" : "No") << endl;
    bc.printUTXO();

    return 0;
}
