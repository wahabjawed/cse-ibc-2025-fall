#include <iostream>
#include <chrono>
#include <ctime>
#include <vector>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

using namespace std;

struct transaction {
  long long amount;
  string sender_addr;
  string reciever_addr;
};

class Block {
private:
  long long index;
  time_t timestamp;
  string prev_hash;
  string hash;
  transaction transact;
  long long nonce;

public:
  Block(long long index, string prev_hash, transaction transact )
    : index(index), prev_hash(prev_hash), nonce(0), transact(transact)
  {
    auto time = chrono::system_clock::now();
    timestamp = chrono::duration_cast<chrono::milliseconds>(time.time_since_epoch()).count();
    hash = compute_hash();
  }
  Block(Block &&) = default;
  Block(const Block &) = default;
  Block &operator=(Block &&) = default;
  Block &operator=(const Block &) = default;
  ~Block() = default;  

  //getters
  long long get_index() const { return index;}
  string get_prev_hash() const {return prev_hash;}
  string get_hash() const {return hash;}
  time_t get_timestamp() const {return timestamp;}
  long long get_nonce() const {return nonce;}

  string compute_hash() const {
    stringstream ss;
    ss << index << prev_hash << timestamp << prev_hash << transact.amount << transact.sender_addr << transact.reciever_addr << nonce;
    string input = ss.str();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    stringstream ss_hash;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      ss_hash << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss_hash.str();
  }

  void mine_block(int difficulty) {
    string target(difficulty, '0');
    while (hash.substr(0, difficulty) != target) {
      nonce++;
      hash = compute_hash();
    }
    cout << "Block mined: " << hash << endl;
  }
};

class Blockchain {
private:
  vector<Block> chain;
  int difficulty;

  Block create_genesis_block() const {
    transaction genesis_transact = {0, "0", "0"};
    return Block(0, "0", genesis_transact);
  }

public: 
  Blockchain(int difficulty) : difficulty(difficulty) {
    chain.push_back(create_genesis_block());
  }
  Blockchain(Blockchain &&) = default;
  Blockchain(const Blockchain &) = default;
  Blockchain &operator=(Blockchain &&) = default;
  Blockchain &operator=(const Blockchain &) = default;
  ~Blockchain() = default;

  void add_block(const transaction& transact) {
    Block new_block(chain.size(), chain.back().get_hash(), transact);
    new_block.mine_block(difficulty);
    chain.push_back(new_block);
  }

  bool is_chain_valid() const {
    for (int i = 1; i < chain.size(); i++) {
      if (chain[i].get_hash() != chain[i].compute_hash()) {
        return false;
      }
      if (chain[i].get_prev_hash() != chain[i-1].get_hash()) {
        return false;
      }
    }
    return true;
  }
};

int main (int argc, char *argv[]) {

  if(argc < 2) {
    cout << "Usage: " << argv[0] << " <difficulty>" << endl;
    return 1;
  }
  const int difficulty = stoi(argv[1]);

  //creating blockchain with genesis block created with constructor
  Blockchain blockchain(difficulty);

  //treating names as addresses for simplicity
  const time_t t0 = chrono::system_clock::to_time_t(chrono::system_clock::now());
  blockchain.add_block({100, "Alice", "Bob"});
  const time_t t1 = chrono::system_clock::to_time_t(chrono::system_clock::now());

  cout << "time taken: " << difftime(t1, t0) << " seconds \n";

  blockchain.add_block({50, "Bob", "Charlie"});
  const time_t t2 = chrono::system_clock::to_time_t(chrono::system_clock::now());

  cout << "time taken: " << difftime(t2, t1) << " seconds \n";

  blockchain.add_block({25, "Charlie", "Dave"});
  const time_t t3 = chrono::system_clock::to_time_t(chrono::system_clock::now());

  cout << "time taken: " << difftime(t3, t2) << " seconds \n\n";

  cout << "Is blockchain valid? " << (blockchain.is_chain_valid()?"true":"false") << endl;

  delete &t0, &t1, &t2, &t3;
  delete &blockchain;
  return 0;
}
