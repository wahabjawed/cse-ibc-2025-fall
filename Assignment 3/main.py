import hashlib
import time
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1

class Transaction:
    """
    Represents a transaction with:
      - sender: sender's public key (hex-encoded)
      - recipient: recipient's address/public key (hex-encoded)
      - amount: integer amount to send
      - signature: digital signature (hex-encoded), verifies the transaction is valid
    """
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        """Convert transaction to dictionary format (useful for hashing and verifying)."""
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount
        }

    def sign_transaction(self, private_key):
        """
        Signs the transaction using the sender's private key.
        In a real system, you should carefully handle the private key.
        """
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        tx_hash = self.calculate_hash()
        sig = sk.sign(tx_hash.encode()).hex()
        self.signature = sig

    def calculate_hash(self):
        """Hash the transaction contents (sender, recipient, amount)."""
        tx_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(tx_str.encode()).hexdigest()

    def is_valid(self):
        """
        Validate transaction by checking signature with the sender’s public key
        and verifying the sender has enough UTXOs to cover the amount.
        (Naive check: only checks the *current* on-chain UTXO balance.)
        """
        # If it's a 'coinbase'/reward transaction (no sender), skip signature check:
        if self.sender is None:
            return True

        # Check that signature is not None
        if not self.signature:
            print("Transaction has no signature.")
            return False

        # Recompute the hash and verify the signature
        tx_hash = self.calculate_hash()
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
            if not vk.verify(bytes.fromhex(self.signature), tx_hash.encode()):
                print("Invalid signature.")
                return False
        except:
            print("Error verifying signature.")
            return False

        # Check if the sender has enough in the UTXO set to cover *this* transaction
        # (Not considering mempool here; see the new check in Blockchain.add_transaction_to_mempool)
        if not UTXO_SET.has_enough_balance(self.sender, self.amount):
            print("Insufficient on-chain funds for this transaction.")
            return False

        return True


class Block:
    """
    Represents a block in the blockchain.
    Each block contains:
      - index
      - timestamp
      - transactions (list of Transaction)
      - previous_hash
      - nonce (for proof-of-work)
      - hash (the block’s own hash)
    """
    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """
        Calculate the block's hash based on its contents:
        index, timestamp, transactions, previous_hash, and nonce.
        """
        block_str = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_str.encode()).hexdigest()

    def mine_block(self, difficulty):
        """
        Simple proof-of-work mining: we look for a hash with 'difficulty' leading zeros.
        """
        target = '0' * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")


class UTXOSet:
    """
    A simple UTXO set that tracks unspent outputs by address.
    utxos[address] = total_balance_of_unspent_coins
    """
    def __init__(self):
        self.utxos = {}

    def get_balance(self, address):
        return self.utxos.get(address, 0)

    def has_enough_balance(self, address, amount):
        """Check if an address has enough unspent coins to send."""
        return self.get_balance(address) >= amount

    def handle_transaction(self, transaction):
        """
        Update the UTXO set when a transaction is confirmed:
         - Subtract from sender’s balance
         - Add to recipient’s balance
        """
        if transaction.sender is not None:
            self.utxos[transaction.sender] = self.get_balance(transaction.sender) - transaction.amount
        self.utxos[transaction.recipient] = self.get_balance(transaction.recipient) + transaction.amount


class Blockchain:
    """
    The Blockchain itself, which holds:
      - a list of blocks
      - a mempool (list of pending transactions)
      - a difficulty for proof-of-work
    """
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.mempool = []

    def create_genesis_block(self):
        """The first block in the chain, usually with a dummy transaction."""
        genesis_tx = Transaction(None, "GENESIS_ADDRESS", 50)  # dummy
        genesis_block = Block(0, [genesis_tx], "0")
        genesis_block.hash = genesis_block.calculate_hash()
        return genesis_block

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction_to_mempool(self, transaction):
        """
        Enhanced check:
          1) Sum up all the amounts the sender has *already* in the mempool.
          2) Compare that plus the new transaction amount to the sender's
             current on-chain UTXO balance.
          3) If the sender doesn't have enough "future" balance, reject.
          4) Otherwise, check signature validity as usual, and add if valid.
        """
        sender = transaction.sender
        if sender is not None:
            # Calculate how much the sender is already spending in the mempool
            mempool_spending = sum(
                tx.amount for tx in self.mempool if tx.sender == sender
            )
            # The sender's current on-chain balance
            current_balance = UTXO_SET.get_balance(sender)

            # If the new tx would exceed the sum of on-chain funds minus existing mempool spends
            if transaction.amount + mempool_spending > current_balance:
                print(
                    f"Rejecting transaction from {sender[:10]}...: "
                    f"Insufficient future balance. Already spending {mempool_spending}, "
                    f"has {current_balance}, needs {transaction.amount} more."
                )
                return

        # Now perform the normal validity checks (signature + naive on-chain check)
        if transaction.is_valid():
            self.mempool.append(transaction)
            print("Transaction added to mempool.")
        else:
            print("Transaction is invalid and was not added.")

    def mine_pending_transactions(self, miner_address):
        """
        Mine a new block of all pending transactions.
        The miner receives a block reward transaction.
        """
        # Add a coinbase / block reward transaction for the miner
        reward_tx = Transaction(None, miner_address, 10)  # 10 is the block reward
        self.mempool.insert(0, reward_tx)

        # Create new block with all pending transactions
        new_block = Block(len(self.chain), self.mempool[:], self.get_latest_block().hash)
        new_block.mine_block(self.difficulty)

        # Add block to the chain
        self.chain.append(new_block)

        # Update UTXO set with new block’s transactions
        for tx in self.mempool:
            UTXO_SET.handle_transaction(tx)

        # Clear the mempool
        self.mempool = []

    def is_chain_valid(self):
        """Check the integrity of the blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i-1]

            # Recalculate hash and compare
            if current_block.hash != current_block.calculate_hash():
                print("Current block hash mismatch!")
                return False

            # Check previous block's hash
            if current_block.previous_hash != prev_block.hash:
                print("Previous block hash mismatch!")
                return False

            # Check each transaction in the block
            for tx in current_block.transactions:
                if not tx.is_valid():
                    print("Invalid transaction in block.")
                    return False

        return True


# Global instance of UTXO set
UTXO_SET = UTXOSet()


class User:
    """
    A user has a public key and a private key (ECDSA).
    The user can create (sign) transactions to pay others.
    """
    def __init__(self):
        private_key_obj = SigningKey.generate(curve=SECP256k1)
        self.private_key = private_key_obj.to_string().hex()
        self.public_key = private_key_obj.get_verifying_key().to_string().hex()

    def create_transaction(self, recipient_address, amount):
        """
        Create and sign a new transaction from this user to `recipient_address`.
        """
        tx = Transaction(self.public_key, recipient_address, amount)
        tx.sign_transaction(self.private_key)
        return tx


def demo():
    # Create a new blockchain
    my_chain = Blockchain(difficulty=2)

    # Create two users
    alice = User()
    bob = User()

    # Fund Alice with 100 units in UTXO set manually (like a faucet)
    UTXO_SET.utxos[alice.public_key] = 100
    print(f"Alice's on-chain balance = {UTXO_SET.get_balance(alice.public_key)}\n")

    # 1) Alice -> Bob for 30
    tx1 = alice.create_transaction(bob.public_key, 30)
    my_chain.add_transaction_to_mempool(tx1)

    # 2) Alice -> Bob for 80 in the same mempool
    #    Now the new logic will check that Alice is already spending 30,
    #    and her total on-chain is 100. So 30 + 80 > 100 => Should be rejected.
    tx2 = alice.create_transaction(bob.public_key, 80)
    my_chain.add_transaction_to_mempool(tx2)

    # We mine, so only the first transaction should be in the block
    print("\nMining pending transactions...")
    miner_address = "Miner1234"
    my_chain.mine_pending_transactions(miner_address)

    # Check Balances after block is mined
    print("\n-- Balances After Mining --")
    print("Alice's Balance:", UTXO_SET.get_balance(alice.public_key))
    print("Bob's Balance:", UTXO_SET.get_balance(bob.public_key))
    print("Miner's Balance:", UTXO_SET.get_balance(miner_address))

    # Demonstrate chain validity
    print("\nIs chain valid?", my_chain.is_chain_valid())


if __name__ == "__main__":
    demo()
