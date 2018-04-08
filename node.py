import json
import os
import threading

from flask import Flask, jsonify, request, render_template
from flask.json import jsonify
from flask_cors import CORS

from core.blockchain import BaobaBlockchain


app = Flask(__name__)

CORS(app)

blockchain = None


FLASK_ROOT = os.path.abspath(os.path.dirname(__file__))
DATA_ROOT = os.path.join(FLASK_ROOT, 'data')


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/transactions/receive', methods=['POST'])
def new_transaction():
    """
    Endpoint that receives transactions from clients.
    """
    values = request.json or request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature', 'payload']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    for key, value in values.items():
        print(key, value, type(value))
    tx_hash, sealed_new_block = blockchain.submit_transaction(values['sender_address'],
                                                              values['recipient_address'],
                                                              float(values['amount']),
                                                              values['signature'],
                                                              values['payload'],
                                                              float(values['timestamp']))

    if tx_hash is False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        if sealed_new_block:
            threading.Timer(1,
                            blockchain.broadcast_new_block,
                            args=[blockchain.chain[-1]],
                            kwargs={'referer': request.referrer}).start()
            response = {'message': 'Your transaction was already added to the latest Block!'}
        else:
            threading.Timer(1, blockchain.notify_peers, args=[tx_hash], kwargs={'referer': request.referrer}).start()
            response = {'message': 'Transaction will be added to Block ' + str(len(blockchain.chain) - 1)}
    return jsonify(response), 201


@app.route('/transactions/notification', methods=['GET'])
def transaction_notification():
    """
    Endpoint to send notifications to by other nodes in the network.
    The notification consists of the transaction hash. In case the node doesn't
    have yet this transaction, send a response with a request to send in
    all transaction details.
    """
    print('got notification')
    transaction_hash = request.args.get('tx_hash', None)

    if blockchain.check_if_transaction_exists(transaction_hash) == -1:
        return jsonify({"send_full_transaction": True}), 200

    return jsonify({"send_full_transaction": False}), 200


@app.route('/block/new', methods=['POST'])
def new_block():
    """
    Endpoint to send new blocks to by other nodes in the network that have sealed them.
    """
    print('got new block from {}!'.format(request.referrer))
    block_details = request.json['block']
    print(block_details['block_number'], block_details['timestamp'])

    # If the received block has the block_number greater
    # than the one which should be next, resolve conflicts.
    if block_details.get('block_number') > len(blockchain.chain):
        conflicts_resolved = blockchain.resolve_conflicts()
        if conflicts_resolved:
            response = {'message': 'Chain updated. Thanks!'}
        else:
            response = {'message': 'Your chain is not valid. I\'ll have to inform the world about this!'}
        return jsonify(response), 200
    elif blockchain.check_if_block_is_valid(block_details) is True:
        blockchain.rollback_current_transactions()
        blockchain.add_block(block_details)
        blockchain.reset_watching_for_blocks()
        response = {'message': 'Bao! Block added successfully, thanks!'}
        return jsonify(response), 200
    else:
        print('Something is wrong with this block. Not added, sorry.')
        response = {'message': 'Something is wrong with this block. Not added, sorry.'}
        return jsonify(response), 406


@app.route('/transactions/details', methods=['POST'])
def transaction_details():
    """
    Endpoint to send a transaction to by another node that first received it from a client.
    """
    print("details received")
    tx = request.json
    tx_hash, sealed_new_block = blockchain.submit_transaction(tx['sender_address'],
                                                              tx['recipient_address'],
                                                              float(tx['amount']),
                                                              tx['signature'],
                                                              tx.get('additional_payload', None),
                                                              tx['timestamp'])

    if tx_hash is False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406

    response = {'message': 'Transaction will be added to Block ' + str(len(blockchain.chain) - 1)}
    return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    """
    Get the transactions from the blockchain.

    In case no query arguments are sent, return the list of transactions waiting to be added to the new block.
    In case there is a `hash` query argument, return the details of the transaction with the given hash.
    """
    tx_hash = request.args.get('hash', None)
    if tx_hash:
        transaction = blockchain.find_transaction(tx_hash)
        response = {'data': transaction}
    else:
        transactions = blockchain.transactions
        response = {'data': transactions}

    return jsonify(response), 200


@app.route('/blocks/update-payload', methods=['POST'])
def update_block_payload():
    payload = request.json['payload']

    blockchain.block_payload = payload

    response = {'message': 'Block payload updated! Until changed, all blocks will have this payload:{}'.format(payload)}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/accounts/balance', methods=['GET'])
def account_balance():
    address = request.args.get('address', None)
    if address:
        response = {'balance': blockchain.accounts.get(address, {}).get('bao', 0)}
    else:
        response = {'balance': None}
    return jsonify(response), 200


@app.route('/blocks/count', methods=['GET'])
def get_block_count():
    """
    According to project specs, return the number of blocks in the chain.
    :return: The number of blocks in the chain.
    """
    response = {'count': len(blockchain.chain)}
    return jsonify(response), 200


@app.route('/blocks/get', methods=['GET'])
def get_block_data():
    """
    According to project specs, return the block transaction data.
    :return: The transaction data in the block.
    """
    block_nr = request.args.get('block_nr', False)
    block_hash = request.args.get('hash', False)

    if not any([block_nr, block_hash]):
        response = {'message': 'You should provide either a block number, or a block hash.'}
    else:
        if block_nr:
            try:
                block_search_prop = 'block_number'
                block_search_value = int(block_nr)
            except ValueError:
                response = {'message': 'Invalid block number. Should be an integer.'}
                return jsonify(response), 400
        else:
            block_search_prop = 'block_header'
            block_search_value = block_hash
        block = blockchain.get_block_data(block_search_prop, block_search_value)
        response = {'data': block}

    return jsonify(response), 200


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

    if not os.path.exists(DATA_ROOT):
        os.makedirs(DATA_ROOT)

    with open(credentials_path, 'r') as credentials_file:
        with open(config_path, 'r') as config_file:
            credentials = json.loads(credentials_file.read())
            config = json.loads(config_file.read())
            if not os.path.exists(os.path.join(DATA_ROOT, credentials['filename'])):
                with open(os.path.join(DATA_ROOT, credentials['filename']), 'w') as f:
                    pass  # just create the file
            blockchain = BaobaBlockchain(config, credentials)

    app.run(host='127.0.0.1', port=port)
