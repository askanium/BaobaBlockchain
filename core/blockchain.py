import hashlib
import json
import os
import threading
import binascii
from collections import OrderedDict
from copy import deepcopy
from operator import indexOf, itemgetter
from time import time
import math

import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


MINING_SENDER = "THE BLOCKCHAIN"
FLASK_ROOT = os.path.abspath(os.path.dirname(__file__))
DATA_ROOT = os.path.join(os.path.split(FLASK_ROOT)[0], 'data')


class BaobaBlockchain(object):
    """
    The core class for the PoA Blockchain.
    """
    def __init__(self, config, credentials):
        self.transactions = []
        self.chain = []

        self.private_key = credentials['private_key']
        self.public_key = credentials['public_key']
        self.filename = credentials['filename']
        self.uri = credentials['uri']

        self.nodes = [node for node in set(config['network']['nodes']) if node != self.uri]
        self.sealing_reward = config['params']['sealingReward']
        self.network_id = config['params']['networkID']
        self.block_period = config['params']['blockPeriod']  # in seconds
        self.nr_of_transactions_per_block = config['params']['nrOfTxsPerBlock']

        # State attributes
        self.valid_signers = [acc for acc, details in config['accounts'].items() if details['is_authority'] is True]
        self.accounts = config['accounts']
        self.temp_state = deepcopy(self.accounts)  # for checking the validity of transaction of the next block

        # Genesis config variables
        self.genesis_config = config['genesis']

        # Needed to be able to seal the first block in ~10 minutes if it will have < 10 transactions.
        self.initialization_timestamp = time()

        self.block_payload = None

        self.valid_signers_block_limit = {signer: 0 for signer in self.valid_signers}

        self.initialize_chain()
        self.initialize_accounts()

        self.watcher_timer = None
        self.reset_watching_for_blocks()

    def initialize_chain(self):
        """
        Either create the first block, or read the chain from the data/chain.baobab file.
        """
        need_to_write_genesis_into_file = True
        with open(os.path.join(DATA_ROOT, self.filename), 'r') as f:
            for block in f.readlines():
                need_to_write_genesis_into_file = False
                # print('block, ', block)
                block = json.loads(block)
                self.chain.append(block)
                self.valid_signers_block_limit[block['signer']] = block['block_number'] + block['signer_limit']

        if need_to_write_genesis_into_file:
            # Create genesis block
            self.chain.append(OrderedDict({
                'block_number': len(self.chain),
                'signer': self.genesis_config['signer'],
                'signer_count': self.genesis_config['signer_count'],
                'signer_limit': self.genesis_config['signer_limit'],
                'timestamp': self.genesis_config['timestamp'],
                'transactions': [],
                'accounts': self.accounts,
                'transactions_merkle_root': self._get_merkle_root_for_transactions(self.transactions),
                'accounts_merkle_root': self._get_merkle_root_for_accounts(self.accounts),
                'additional_payload': self.genesis_config['extraData'],
                'previous_block_hash': self.genesis_config['parentHash'],
            }))
            self.chain[0]['block_header'] = self.hash(self.chain[0])
            self.accounts = deepcopy(self.accounts)

            with open(os.path.join(DATA_ROOT, self.filename), 'w') as f:
                f.write(json.dumps(self.chain[0]))

    def initialize_accounts(self):
        """
        Initialize the accounts based on the latest block.
        """
        self.accounts = self.recompute_state_for_block(self.chain[-1], from_genesis=True)

    @staticmethod
    def verify_transaction_signature(sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        # Re-create a tx with only the relevant keys to sign.
        tx = OrderedDict({key: transaction[key]
                          for key in ['recipient_address',
                                      'sender_address',
                                      'amount',
                                      'timestamp',
                                      'additional_payload'
                                      ]})
        try:
            public_key = RSA.importKey(binascii.unhexlify(sender_address))
        except Exception as e:
            print(e)
            return False
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(tx).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def submit_sealing_reward_transaction(self, recipient_address):
        """
        Add the transaction that emits the sealing reward.
        :param recipient_address: The address that has to receive the reward.
        """
        transaction = Transaction(recipient_address, MINING_SENDER, self.sealing_reward)
        tx_dict = transaction.to_dict()
        self.process_transaction(tx_dict)
        self.transactions.append(tx_dict)
        tx_dict['hash'] = self.hash(tx_dict, is_block=False)
        return tx_dict['hash']

    def submit_transaction(self, sender_address, recipient_address, amount, signature, additional_payload=None, timestamp=None):
        """
        Submit a transaction to be processed and added to the blockchain.
        :param sender_address: The address of the sender account.
        :param recipient_address: The address of the recipient account.
        :param amount: The amount to transfer.
        :param signature: The signature of the transaction.
        :param additional_payload: The additional payload to be included in transaction.
        :param timestamp: The timestamp of the transaction.
        :return: A tuple consisting of the transaction hash (or None, in case of invalid transaction)
            and a flag to indicate whether after processing the transaction a block was created.
        """
        block_sealed = False

        # In case this is the transaction that rewards the sealer with 100 coins, generate the timestamp now.
        timestamp = timestamp or time()

        transaction = Transaction(recipient_address, sender_address, amount,
                                  additional_payload=additional_payload, timestamp=timestamp)

        tx_hash = self.handle_transaction(transaction, sender_address, signature)
        if tx_hash is False:
            return False, False
        if self._can_seal_block():
            self.seal_block()
            block_sealed = True

        return tx_hash, block_sealed

    def handle_transaction(self, transaction, sender, signature, tx_as_dict=False):
        """
        Validate and process a transaction.

        This process is divided into several steps:
            1. First, verify the transaction signature. If that is valid, move on, otherwise return False
            2. If the TXs timestamp is smaller than the latest tx in the list, then:
                a. Roll back the state for the current block.
                b. Create a copy of the sorted TXs based on their timestamp.
                c. Re-submit each TX to sort out those that aren't valid based on the account values.
                otherwise, proceed further.
            3.
        :param transaction: The transaction to be handled.
        :param sender: The sender address of the transaction.
        :param signature: The signature of the transaction.
        :param tx_as_dict: Flags whether the transaction argument is an object or a dict.
        :return: The hash of the processed transaction or False, in case transaction is invalid.
        """
        if not tx_as_dict:
            tx_dict = transaction.to_dict()
        else:
            tx_dict = transaction

        tx_is_valid = self.verify_transaction_signature(sender, signature, tx_dict)
        if tx_is_valid:
            if len(self.transactions) and tx_dict['timestamp'] < self.transactions[-1]['timestamp']:
                tx_dict['signature'] = signature
                tx_dict['hash'] = self.hash(tx_dict, is_block=False)

                # This is to know which value to return to the handle_transaction call that has
                # submitted the transaction with a timestamp < than the timestamp of latest tx.
                past_timestamp_tx_hash = False

                self.rollback_current_transactions()
                temp_txs = sorted([tx_dict, *self.transactions], key=itemgetter('timestamp'))
                self.transactions = []

                # For each transaction, resubmit it and recompute the state.
                for idx, tx in enumerate(temp_txs):

                    # In case there will be 2 transactions with the same timestamp and sender address, which will
                    # most likely be an attempt to double spend some coins, simply discard the second transaction.
                    if idx > 0 \
                            and temp_txs[idx]['timestamp'] == temp_txs[idx - 1]['timestamp'] \
                            and temp_txs[idx]['sender_address'] == temp_txs[idx - 1]['sender_address']:
                        continue

                    # Re-submit the transaction to be validated and processed.
                    tx_hash = self.handle_transaction(tx, tx['sender_address'], tx['signature'], tx_as_dict=True)

                    # If the hash equals to the hash of the TX that had the timestamp value < than the
                    # timestamp of last TX, then notify the called that that TX is valid and was added.
                    if tx_hash == tx_dict['hash']:
                        past_timestamp_tx_hash = tx_hash
                return past_timestamp_tx_hash
            else:
                tx_process_status = self.process_transaction(tx_dict)
                if tx_process_status is True:
                    tx_dict['signature'] = signature
                    tx_dict['hash'] = self.hash(tx_dict, is_block=False)
                    self.transactions.append(tx_dict)
                    return tx_dict['hash']
                else:
                    return False
        else:
            return False

    def process_transaction(self, transaction):
        """
        Process a given transaction that was verified to be valid.

        Processing a transaction happens in several steps:
            1. Verify if the sender has enough balance indicated in the transaction. If the amount is bigger than
                the sender's balance, reject the transaction.
            2. If the receiver's account doesn't exist, create it.
            3. Transfer the transaction value from sender to receiver.
        :param transaction: Transaction
        :return: A boolean value that indicates whether the transaction was successfully processed or not.
        """
        sender = transaction['sender_address']
        recipient = transaction['recipient_address']
        amount = transaction['amount']
        if sender != MINING_SENDER and self._check_if_account_has_enough_bao(sender, amount) is False:
            return False
        if amount <= 0:
            return False
        self._check_recipient_account(recipient)
        self._transfer_bao_between_accounts(sender, recipient, amount)
        return True

    def _check_if_account_has_enough_bao(self, account_address, amount):
        """
        Check if an account has the specified amount of bao.
        :param account_address: The address which to verify.
        :type account_address: str
        :param amount: The amount which and address should contain.
        :type amount: float
        :return: Whether the given account contains at least the specified amount.
        :rtype: bool
        """
        return self.accounts.get(account_address, {}).get("bao", -1) >= amount

    def _check_recipient_account(self, recipient_address):
        """
        If the recipient's address doesn't exist, create it, otherwise do nothing.
        :param recipient_address: The address of the recipient of the transaction's amount.
        :type recipient_address: str
        :return: Whether the address was created or not.
        :rtype: bool
        """
        if recipient_address not in self.accounts:
            self.accounts[recipient_address] = {
                "bao": 0.0,
                "is_authority": False
            }
            return True
        return False

    def _transfer_bao_between_accounts(self, sender_address, recipient_address, amount):
        """
        Make the actual transfer of the amount of bao from the sender to the recipient.
        :param sender_address: The address from which to transfer bao.
        :param recipient_address: The address to which to transfer bao.
        :param amount: The amount to transfer.
        :type sender_address: str
        :type recipient_address: str
        :type amount: float
        """
        if sender_address != MINING_SENDER:
            self.accounts[sender_address]["bao"] -= amount
        self.accounts[recipient_address]["bao"] += amount

    def create_block(self, previous_block_hash, signer):
        """
        Add a block of transactions to the core
        """
        # `signer_limit` value is according to Clique PoA consensus protocol
        # (https://github.com/ethereum/EIPs/issues/225)
        block = OrderedDict({
            'block_number': len(self.chain),
            'signer': signer,
            'signer_count': len(self.valid_signers),
            'signer_limit': math.floor(len(self.valid_signers) / 2) + 1,
            'signer_index': indexOf(self.valid_signers, signer),
            'timestamp': time(),
            'transactions': self.transactions,
            'additional_payload': self.block_payload,
            'transactions_merkle_root': self._get_merkle_root_for_transactions(self.transactions),
            'previous_block_hash': previous_block_hash
        })

        block['block_header'] = self.hash(block)
        block['signature'] = self._sign_block(block)

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)

        return block

    def _sign_block(self, block):
        """
        Sign block with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(block['block_header'].encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def verify_block_signature(self, public_key, signature, block):
        """
        Check that the provided signature corresponds to block
        signed by the public key (public_key)
        """
        # If the signer is not in the list of valid_signers, invalidate the block.
        if public_key not in self.valid_signers:
            return False

        try:
            public_key = RSA.importKey(binascii.unhexlify(public_key))
        except Exception:
            return False
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(block['block_header'].encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def rollback_current_transactions(self, copy=False):
        """
        Compute the state as it was for the previous block.
        :param copy: A flag that indicates whether to create a copy of the accounts before rolling back transactions.
        :return: The state of accounts as it was right after sealing the last block.
        """
        if copy:
            accounts = deepcopy(self.accounts)
        else:
            accounts = self.accounts
        for tx in self.transactions:
            if tx['sender_address'] != MINING_SENDER:
                accounts[tx['sender_address']]['bao'] += tx['amount']
            accounts[tx['recipient_address']]['bao'] -= tx['amount']
        return accounts

    def add_block(self, block):
        """
        Add the given block to the core.
        :param block: The block to be added.
        :return: The new length of the core.
        """
        self.transactions = []
        self.chain.append(block)
        for tx in block.get('transactions'):
            if tx['sender_address'] != MINING_SENDER:
                self.accounts[tx['sender_address']]['bao'] -= tx['amount']
            self.accounts[tx['recipient_address']]['bao'] += tx['amount']
        self.save_sealed_block(block)
        self.valid_signers_block_limit[block['signer']] = block['block_number'] + block['signer_limit']

        return len(self.chain)

    def check_if_block_is_valid(self, block):
        """
        Check whether a received block is valid and can be added to the core.
        :param block: The block that needs to be verified.
        :return: Whether the block is valid or not.
        """
        next_block_number = len(self.chain)
        prev_timestamp = self.chain[-1]['timestamp']
        prev_block_hash = self.chain[-1]['block_header']
        unsatisfied_conditions = 0

        block['transactions'] = sorted(block['transactions'], key=itemgetter('timestamp'))

        if block.get('block_number', None) != next_block_number:
            print('wrong block number: {}'.format(block.get('block_number')))
            unsatisfied_conditions += 1
        if block.get('signer', None) not in self.valid_signers:
            print('signer not in valid signers')
            unsatisfied_conditions += 1
        if block.get('timestamp', 0) < prev_timestamp:
            print('wrong timestamp')
            unsatisfied_conditions += 1
        if len(block.get('transactions', [])) < self.nr_of_transactions_per_block + 1 \
                and block.get('timestamp', self.block_period + 1) < self.block_period:
            print('earlier than 10 minutes for block with no transactions')
            unsatisfied_conditions += 1
        if block.get('previous_block_hash', None) != prev_block_hash:
            print('wrong prev block hash')
            unsatisfied_conditions += 1
        if block.get('block_number', 0) < self.valid_signers_block_limit.get(block.get('signer', None), 1):
            print('wrong signer signed block')
            unsatisfied_conditions += 1
        if self.verify_block_signature(block.get('signer', ''), block.get('signature', ''), block) is False:
            print('wrong block signature')
            unsatisfied_conditions += 1

        unsatisfied_conditions += self._check_block_accounts_and_transactions_validity(block)

        return unsatisfied_conditions == 0

    def _check_block_accounts_and_transactions_validity(self, block):
        """
        Check whether the accounts in the newly sealed block are valid.
        :param block: The block to check.
        :return: Number of invalid accounts.
        """
        unsatisfied_conditions = 0
        nr_of_sealing_reward_transactions = 0
        accounts = self.rollback_current_transactions(copy=True)
        for tx in block.get('transactions', []):
            # Create the recipient address if it didn't exist before the new block.
            if tx['recipient_address'] not in accounts:
                accounts[tx['recipient_address']] = {'bao': 0, 'data': None}

            if tx['sender_address'] == MINING_SENDER:
                nr_of_sealing_reward_transactions += 1
            else:
                if tx['sender_address'] not in accounts:
                    unsatisfied_conditions += 1
                    return unsatisfied_conditions

                # Because order of transactions matter and because in the same block
                # might exist a transaction from A->B and the B->C, we need to adjust
                # the value of each account after each transaction, so that B will be
                # able to spend the bao coins received by A.
                accounts[tx['sender_address']]['bao'] -= tx['amount']
                accounts[tx['recipient_address']]['bao'] += tx['amount']

                if tx['sender_address'] in accounts and accounts[tx['sender_address']]['bao'] < tx['amount']:
                    unsatisfied_conditions += 1

            if self._check_new_block_transaction_validity(tx) is False:
                unsatisfied_conditions += 1

        if nr_of_sealing_reward_transactions > 1:
            unsatisfied_conditions += 1

        return unsatisfied_conditions

    def _check_new_block_transaction_validity(self, tx):
        """
        Check whether the transaction in the new block is valid.
        :param tx: The transaction to be checked.
        :return: True or False, depending on transaction validity.
        """
        tx_dict = OrderedDict({
            key: tx[key]
            for key in ['recipient_address', 'sender_address', 'amount', 'timestamp', 'additional_payload']
        })
        if tx['sender_address'] != MINING_SENDER \
                and self.verify_transaction_signature(tx['sender_address'], tx['signature'], tx_dict) is False:
            return False
        elif tx['sender_address'] == MINING_SENDER:
            if tx['amount'] != self.sealing_reward:
                return False
        return True

    @staticmethod
    def _get_merkle_root_for_transactions(transactions):
        """
        Compute the merkle root of the transactions in the block.
        :param transactions: The transactions to process into a Merkle root.
        :return: The Merkle Root hash.
        """
        tx_hashes = [tx['hash'] for tx in sorted(transactions, key=itemgetter('hash'))]
        if len(tx_hashes) == 0:
            return hashlib.sha256(hashlib.sha256(''.encode()).digest()).hexdigest()
        elif len(tx_hashes) == 1:
            return hashlib.sha256(hashlib.sha256((tx_hashes[0] + tx_hashes[0]).encode()).digest()).hexdigest()
        elif len(tx_hashes) == 2:
            return hashlib.sha256(hashlib.sha256((tx_hashes[0] + tx_hashes[1]).encode()).digest()).hexdigest()
        elif len(tx_hashes) % 2 == 1:
            tx_hashes.append(tx_hashes[-1])

        while True:
            next_level = list()
            for i in range(0, len(tx_hashes), 2):
                next_level.append(hashlib.sha256(hashlib.sha256((tx_hashes[i] + tx_hashes[i+1]).encode()).digest()).hexdigest())

            if len(next_level) == 2:
                return hashlib.sha256(hashlib.sha256(''.join(next_level).encode()).digest()).hexdigest()

            elif len(next_level) % 2 == 1:
                next_level.append(next_level[-1])

            tx_hashes = next_level

    @staticmethod
    def _get_merkle_root_for_accounts(accounts):
        """
        Compute the merkle root of the accounts in the block.
        :param accounts: The accounts to process into a Merkle root.
        :return: The Merkle Root hash.
        """
        acc_hashes = sorted([hashlib.sha256(json.dumps({address: details}).encode()).hexdigest()
                             for address, details in accounts.items()])
        if len(acc_hashes) % 2 == 1:
            acc_hashes.append(acc_hashes[-1])

        while True:
            next_level = list()
            for i in range(0, len(acc_hashes), 2):
                next_level.append(hashlib.sha256(hashlib.sha256((acc_hashes[i] + acc_hashes[i+1]).encode()).digest()).hexdigest())

            if len(next_level) == 2:
                return hashlib.sha256(hashlib.sha256(''.join(next_level).encode()).digest()).hexdigest()

            elif len(next_level) % 2 == 1:
                next_level.append(next_level[-1])

            acc_hashes = next_level

    def _can_seal_block(self):
        """
        Check whether the sealer is in turn to seal blocks.
        :return: Whether the block can or cannot be sealed.
        """
        last_timestamp = self.chain[-1].get('timestamp') if len(self.chain) > 1 else self.initialization_timestamp
        # If there are 10 transactions and node can sign (the first block starts at number 0), return True.
        if (len(self.transactions) == self.nr_of_transactions_per_block
            or time() - last_timestamp >= self.block_period) \
                and self.valid_signers_block_limit[self.public_key] <= len(self.chain):
                # and time() - self.chain[-1].get('timestamp') >= self.block_period:
            return True
        return False

    def seal_block(self):
        """
        Seal a block with all the current transactions.
        """
        last_block = self.chain[-1]

        self.submit_sealing_reward_transaction(self.public_key)

        # Forge the new Block by adding it to the chain
        previous_block_hash = self.hash(last_block)
        block = self.create_block(previous_block_hash, self.public_key)
        self.valid_signers_block_limit[self.public_key] = block['block_number'] + block['signer_limit']
        self.save_sealed_block(block)
        self.reset_watching_for_blocks()

        return block

    def save_sealed_block(self, block):
        """
        Store the sealed block in the chain.baobab.
        :param block: The newly sealed block.
        """
        with open(os.path.join(DATA_ROOT, self.filename), 'a') as f:
            f.write('\n')
            f.write(json.dumps(block))

    @staticmethod
    def hash(obj, is_block=True):
        """
        Create a SHA-256 hash of a obj.

        In case the object is a block, compute the hash based on a specific set of headers only.
        """
        if is_block:
            header_keys = ['block_number', 'signer', 'signer_count', 'signer_limit', 'timestamp', 'additional_payload',
                           'transactions_merkle_root', 'accounts_merkle_root']
            obj_string = ''.join([str(obj.get(key, '')) for key in header_keys]).encode()

        else:
            tx_keys = ['sender_address', 'recipient_address', 'amount', 'additional_payload']
            obj_string = ''.join([str(obj[key]) for key in tx_keys]).encode()

        return hashlib.sha256(obj_string).hexdigest()

    def recompute_state_for_block(self, block, from_genesis=False):
        """
        Compute the state with accounts for the given block.
        :param block: The block for which to compute the state.
        :param from_genesis: Whether the state should be computed from genesis block,
            or rolled back from the latest state.
        :return: The recomputed state.
        """
        if from_genesis:
            accounts = deepcopy(self.chain[0]['accounts'])
            sign = 1
            current_block = self.chain[0]
        else:
            accounts = deepcopy(self.accounts)
            sign = -1
            current_block = self.chain[-1]
        while current_block.get('block_number') != block.get('block_number'):
            for tx in current_block.get('transactions'):
                if tx['recipient_address'] not in accounts:
                    accounts[tx['recipient_address']] = {
                        "bao": 0,
                        "is_authority": False
                    }
                if tx['sender_address'] != MINING_SENDER:
                    accounts[tx['sender_address']]['bao'] -= sign * tx['amount']
                accounts[tx['recipient_address']]['bao'] += sign * tx['amount']
            current_block = self.chain[current_block.get('block_number') + sign]

        # If going from genesis block, need to process the last block as well.
        if from_genesis:
            for tx in current_block.get('transactions'):
                if tx['recipient_address'] not in accounts:
                    accounts[tx['recipient_address']] = {
                        "bao": 0,
                        "is_authority": False
                    }
                if tx['sender_address'] != MINING_SENDER:
                    accounts[tx['sender_address']]['bao'] -= sign * tx['amount']
                accounts[tx['recipient_address']]['bao'] += sign * tx['amount']

        return accounts

    def valid_chain(self, chain):
        """
        Check if the chain is valid.
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            # Check that the hash of the block is correct
            if block['previous_block_hash'] != self.hash(last_block):
                return False

            if not self.verify_block_signature(block['signer'], block['signature'], block):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between core's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            with open(os.path.join(DATA_ROOT, self.filename), 'w') as f:
                for i, block in enumerate(self.chain):
                    if i > 0:
                        f.write('\n')
                    f.write(json.dumps(block))
            return True

        return False

    def check_if_transaction_exists(self, tx_hash):
        """
        Check whether a transaction with the given hash is already present in the transactions list.
        :param tx_hash: The hash of the transaction.
        :return: The index of the given transaction from the list of block's transactions or -1 if not found.
        """
        for idx, tx in enumerate(self.transactions):
            if tx_hash == self.hash(tx, is_block=False):
                return idx
        return -1

    def get_transaction_by_hash(self, tx_hash):
        """
        Find the transaction by its hash.
        :param tx_hash: The hash of transaction to find.
        :return: The transaction with its details.
        """
        for tx in self.transactions:
            if tx['hash'] == tx_hash:
                return tx

    def notify_peers(self, tx_hash, referer=None):
        """
        Notify other nodes with the obtained transaction hash.
        :param tx_hash: The hash of the received transaction.
        :param referer: The address that has sent in the notification.
            This is used in order to avoid infinite loops of notification.
        """
        notified_peers = list()
        for uri in self.nodes:
            if uri != self.uri and uri != referer:
                headers = {'content-type': 'application/json', 'referer': self.uri}
                try:
                    r = requests.get(f'{uri}/transactions/notification', headers=headers, params={'tx_hash': tx_hash})
                    if r.status_code == 200:
                        notified_peers.append(True)
                        response = r.json()
                        print('got response after notification', response)
                        if response['send_full_transaction']:
                            tx = self.get_transaction_by_hash(tx_hash)
                            print('sending transaction: {}'.format(tx_hash))
                            requests.post(f'{uri}/transactions/details',
                                          headers=headers,
                                          data=json.dumps({'tx_hash': tx_hash, **tx}))
                    else:
                        notified_peers.append(False)
                except ConnectionError:
                    notified_peers.append(False)
        if not any(notified_peers):
            print('Weird... This node is all by itself :(')
            # TODO implement some notification mechanism that no nodes respond.

    def broadcast_new_block(self, block, referer=None):
        """
        Notify other nodes about the newly sealed block.
        :param block: The block that was sealed.
        :param referer: The node that sent in the block. In a real world scenario, this should be taken
            from the request headers, but here we will put it manually.
        """
        print('broadcasting block...')
        notified_peers = list()
        for uri in self.nodes:
            if uri != self.uri and uri != referer:
                try:
                    headers = {'content-type': 'application/json', 'referer': self.uri}
                    r = requests.post(f'{uri}/block/new', data=json.dumps({'block': block}), headers=headers)
                    if r.status_code == 200:
                        notified_peers.append(True)
                        response = r.json()
                        print('got response after notification')
                        print(response)
                    else:
                        notified_peers.append(False)
                except ConnectionError:
                    notified_peers.append(False)
        if not any(notified_peers):
            print('Weird... This node is all by itself :(')
            # TODO implement some notification mechanism that no nodes respond.

    def reset_watching_for_blocks(self):
        """
        Start or reset the counter when a block is sealed before 10 minutes.
        """
        if self._can_seal_block() and self.watcher_timer:
        # if self._can_seal_block(the_time_has_come=True) and self.watcher_timer:
            block = self.seal_block()
            self.broadcast_new_block(block)

        if self.watcher_timer is not None:
            self.watcher_timer.cancel()
        self.watcher_timer = threading.Timer(self.block_period, self.reset_watching_for_blocks)
        self.watcher_timer.daemon = True
        self.watcher_timer.start()

    def get_block_data(self, search_prop, search_value):
        """
        Search for the given block according to the given block property's value.
        :param search_prop: The property based on which to find the block (e.g. block_header, block_number, etc.).
        :param search_value: The value to search for in the block.
        :return: The corresponding block, or None, if no block found.
        """
        needed_block = None
        for block in self.chain:
            if block[search_prop] == search_value:
                needed_block = block
        return needed_block

    def find_transaction(self, tx_hash):
        """
        Find and return the details of the transaction with the given hash.
        :param tx_hash: The hash of the transaction.
        :return: The transaction details, or None, in case no TX found.
        """
        tx_details = None
        for block in self.chain:
            for tx in block['transactions']:
                if tx['hash'] == tx_hash:
                    tx_details = tx
        return tx_details


class Transaction(object):
    """
    Defines the transaction structure in the core.
    """

    def __init__(self, recipient_address, sender_address, amount, additional_payload=None, timestamp=None):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.additional_payload = additional_payload
        self.timestamp = timestamp or time()

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({
            'recipient_address': self.recipient_address,
            'sender_address': self.sender_address,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'additional_payload': self.additional_payload
        })

    def sign_transaction(self, account_private_key):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(account_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')