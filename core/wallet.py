import hashlib
import json
import os
import threading
from collections import OrderedDict, Counter

import Crypto
import Crypto.Random
import binascii
import requests
from Crypto.PublicKey import RSA


FLASK_ROOT = os.path.abspath(os.path.dirname(__file__))
DATA_ROOT = os.path.join(os.path.split(FLASK_ROOT)[0], 'data')


class Wallet(object):

    def __init__(self, config, credentials=None, credentials_path=None):
        if not credentials:
            credentials = self.__generate_wallet()
        self.private_key = credentials['private_key']
        self.public_key = credentials['public_key']
        self.balance = credentials.get('balance', 0)
        self.nodes = set(config['network']['nodes'])
        self.credentials_path = credentials_path or os.path.join(DATA_ROOT, '{}.wlt'.format(
            hashlib.sha256(self.public_key.encode()).hexdigest()
        ))

        self.watcher_timer = None

        self.set_balance_auto_update_timer()

    @staticmethod
    def __generate_wallet():
        """
        Create a new keypair of public/private keys to be used by the core.
        """
        random_gen = Crypto.Random.new().read
        private_key = RSA.generate(1024, random_gen)
        public_key = private_key.publickey()

        return {
            'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
            'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
        }

    def to_dict(self):
        return OrderedDict({
            'private_key': self.private_key,
            'public_key': self.public_key,
            'balance': self.balance
        })

    def save(self):
        """
        Save the wallet to disk.
        """
        with open(self.credentials_path, 'w') as f:
            f.write(json.dumps(self.to_dict()))

    def update_balance(self):
        """
        Update the balance of the wallet from the network.
        """
        responses = []
        for node in self.nodes:
            response = requests.get('{}/accounts/balance?address={}'.format(node, self.public_key))
            if response.status_code == 200:
                responses.append(response.json()['balance'])

        if len(responses) > 0:
            # Get the amount that is most common among the nodes.
            c = Counter(responses)
            if c.most_common(1)[0][0] != self.balance:
                self.balance = c.most_common(1)[0][0]
                self.save()
                print('Saving your account at: {}'.format(self.credentials_path))
        else:
            print('Strange, nobody answered... Are you online?')
        return self.balance

    def set_balance_auto_update_timer(self):
        """
        Set the timer to auto update wallet balance once in 20 seconds.
        """
        if self.watcher_timer:
            self.update_balance()

        if self.watcher_timer is not None:
            self.watcher_timer.cancel()

        self.watcher_timer = threading.Timer(20, self.set_balance_auto_update_timer)
        self.watcher_timer.daemon = True
        self.watcher_timer.start()
