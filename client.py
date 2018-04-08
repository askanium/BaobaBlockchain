import binascii
from collections import Counter

import Crypto
import Crypto.Random
import requests
from Crypto.PublicKey import RSA

from flask import Flask, jsonify, request, render_template, json

from core.blockchain import Transaction
from core.wallet import Wallet


wallet = None
config = None

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('./client/index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('./client/make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./client/view_transactions.html')


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_address = wallet.public_key
    sender_private_key = wallet.private_key
    recipient_address = request.form['recipient_address']
    value = float(request.form['amount'])
    payload = request.form['payload']

    transaction = Transaction(recipient_address, sender_address, value, additional_payload=payload)

    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction(sender_private_key)}

    return jsonify(response), 200


@app.route('/balance/update', methods=['GET'])
def update_balance():
    responses = []

    for node in wallet.nodes:
        response = requests.get('{}/account/balance?address={}'.format(node, wallet.public_key))
        if response.status_code == 200:
            print('got response', response.json())
            responses.append(response.json()['balance'])

    if len(responses) > 0:
        # Get the amount that is most common among the nodes.
        c = Counter(responses)
        wallet.balance = c.most_common(1)[0][0]
        wallet.save()
    else:
        print('Strange, nobody answered... Are you online?')

    return jsonify({}), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    parser.add_argument('-k', '--credentials', type=str, help='file with encryption keys')
    parser.add_argument('-c', '--config', type=str, help='genesis block config file')
    args = parser.parse_args()
    port = args.port
    credentials_path = args.credentials
    config_path = args.config

    if credentials_path:
        with open(credentials_path, 'r') as credentials_file:
            credentials = json.loads(credentials_file.read())
    else:
        credentials = None

    with open(config_path, 'r') as config_file:
        config = json.loads(config_file.read())

    wallet = Wallet(config, credentials=credentials, credentials_path=credentials_path)

    app.run(host='127.0.0.1', port=port)
