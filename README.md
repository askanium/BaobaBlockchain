# BaobaBlockhain Test Project For Toptal blockchain-academy

The current project is a test blockchain based on the Proof of Authority Consensus algorithm and has implemented
the specifications from the blockchain-academy test project document description.

It is implemented as a Flask app with basic UI.

The currency within the blockchain is named BAO, and this name is used throughout the project.

Below you can find a description of each point from the specifications and some instructions.

#### Running on at least 2 pre-defined nodes

In order to run the BaobaBlockchain, please specify the list of IP addresses in the core/baobablockchain.json file
(the genesis file) under the "network" > "nodes".

#### Proof of Authority consensus algorithm

Please specify the list of authorities under the "accounts" property in the genesis file.

Note that `"accounts"` has the following structure:

```
{
    "accounts": {
        <public_key>: {
            "bao": <amount>,
            "is_authority": true
        },
        ... // other accounts
    },
    ... // other configs in genesis file
}
```

*Important!* For this project, the number of authority accounts should equal the number of nodes defined in the
genesis file.

However, you can define other "regular" accounts and their corresponding balance.

Note that you will have to substitute the accounts from the genesis file as you don't have the matching private_keys for
them. In order to generate a matching public/private key pairs, you can run a client (see below) and use the
`Wallet Generator` option that will generate as many public/private keys as you need.

#### Blocks are mined once in ~10 minutes or when there are 10 TXs

These settings can be adjusted in the genesis file though, by modifying the `"nrOfTxsPerBlock"` and `"blockPeriod"`
values under the `"params"` property. Note that block period value is in seconds.

#### The mining operation involves signing the block by the miner

When a miner creates a block, it first creates a hash of the following keys:

- block_number
- signer
- signer_count
- signer_limit
- timestamp
- additional_payload
- transactions_merkle_root
- accounts_merkle_root  <- currently only for genesis, but can be done once in N blocks

This hash is stored in the `'block_header'` property of the block.

The signature of the block consists of signing the `block_header` with the node's `private_key` and adding the resulting
signature to the block under the `signature` property.

#### Each block rewards 100 coins to the miner

When a miner can seal a block, it adds a transaction where the `sender_address` has the value `"THE BLOCKCHAIN"` which
means that this TX rewards the miner with 100 BAO.

If there are < 10 TXs at the sealing time (or even 0 TXs), the rewards transaction is added nevertheless.

#### Any public key digital signature is acceptable

This project uses RSA-based signature scheme.

#### Addresses may be public keys

The generated public_keys are used as addresses in this project and namely these public_key values should be used
in the genesis and account files when defining accounts and authorities.

#### Any transaction format/type of accounting is acceptable

Current project uses account-based accounting, similar to the Ethereum states.

#### There is a protection against double spending of coins

As the blockchain uses an Ethereum alike type of accounting, transaction processing happens as they arrive to the node.

The processing of transactions happens based on their accompanying timestamp values. If a transaction is sent with the
timestamp X from sender A -> B and after that another transaction is sent with timestamp Y (Y<X) from A -> C,
then the blockchain will reprocess the transactions based on their timestamp values so that if the second (A->C)
invalidates the first (A->B) transaction, only the second will be added to the blockchain.

Hopefully that should be enough for the test project, although in reality a research should be made on the possible
attack vectors for such accounting type.

#### Transactions can have additional data payload within the transaction

The transaction object sent to the node has the following structure:

```
{
  "recipient_address": str,
  "sender_address": str,
  "amount": float,
  "timestamp": float,
  "payload": str,
  "signature": str,
}
```

The signature is created based on an `OrderedDict` in Python, that has all the keys except the `signature` key from
above, in the order indicated in the object above.

This is the code that signs the transaction in case you want to sign it manually and send it to the nodes.

```
private_key = RSA.importKey(binascii.unhexlify(account_private_key))
signer = PKCS1_v1_5.new(private_key)
h = SHA.new(str(self.to_dict()).encode('utf8'))  # <-- self is the OrderedDict instance described above
return binascii.hexlify(signer.sign(h)).decode('ascii')
```

#### Blocks can have additional data payload within the block

In order to update block payload, a POST request should be made to the `/blocks/update-payload` path, specifying
the new payload with `{'payload': string}`.

Note that the payload is defined and updated *per each node individually*.

#### Implement a simple REST-like web service API

The API is the following:

Query the block count: `GET /blocks/count` - returns `{'count': number}`

Query a single block and return all its data: `GET /blocks/get`

One of 2 query parameters are required for `/blocks/get`:

- `block_nr` that indicates the block order in the blockchain to return
- `hash` of the block to return

Query a single transaction and return all its data: `GET /transactions/get`

If called without query parameters, it returns all transactions that are waiting to be added to blocks. However, if
called with a `hash` query parameter, finds and returns the transaction with the given hash.

Create a transaction and send it to be mined: `POST /transactions/receive`

The endpoint expects the following data structure:

```
{
  "recipient_address": str,
  "sender_address": str,
  "amount": float,
  "timestamp": float,
  "payload": str,
  "signature": str,
}
```

## User Interface

The blockchain has a simple user interface that facilitates creating transactions and viewing the already added
transactions to the blockchain as well as those transactions that are waiting to be added to the chain.

The UI was adjusted from the UI of the Adil Moujahid's (example)[http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/],
but everything else is my own work.

To use the UI, simply navigate to the corresponding URL that the Flask app is running on.

## Instruction to launch the nodes and clients

In order to launch the nodes, some additional work needs to be done besides adjusting data in genesis file.

### 1. Set up the environment

Create a virtual environment with Python 3.5+ interpreter, activate it and run `pip install -r requirements.txt` in
order to install all the required dependencies.

### 2. Create a credential file for each node

The file in JSON format should have the following information:

```
# node1.json
{
    "uri": "http://127.0.0.1:5001",
    "filename": "chain1.baobab",
    "private_key": str,
    "public_key": str
}
```

The `uri` is the address the Flask app will be running on.

The `filename` is used to store the blockchain contents in. A file with the corresponding filename will be created under
`data/<filename>`, where the contents of the blockchain will be updated as new blocks will be sealed.

Note that if you will be running the nodes from the same project location (on the same machine on different ports),
you will need to specify different filenames in order not to have several nodes operate on the same blockchain file.

### 3. Create Wallets for nodes and clients

Currently, the blockchain can automatically create a wallet only for a simple user (more on this later).

In order to use the client UI, you should create a `.wlt` file with the following contents:

```
# client1.json
{
    "private_key": str,
    "public_key": str
}
```

It will auto-update with the account balance once the client is up and running.

### 4. Run the nodes

This is an example of the command to run a node:

`(venv) python node.py -p 5003 -k node3.json -c core/baobablockchain.json`

The `-p` is the port to run the node on.

The `-k` is the path to credentials file (from the step 2 from above)

The `-c` is the path to the genesis file

*Important!* You need to run all the nodes defined in the genesis file in order for the blockchain to function properly.

### 5. Run the clients

Finally, in order to make transactions from UI (even for nodes), you need to run the client apps.

`python client.py -p 5005 -c core/baobablockchain.json -k data/client.wlt`

Similarly, `-p` is the port, `-c` is the genesis file (to have addresses of nodes where to send transactions) and
`-k` is the credentials file.

Note that the `-k` option is optional. In case you run a client without the `-k` flag, a new wallet is automatically
generated in the `data/` folder under the project root with a unique filename. The next time you will run the client,
you will still need to provide the path to that file in order to be able to use the balance in it.

## Conclusion

This was a tough, but very interesting and insightful experience, where I have learned a great deal about blockchains.

There are tons of things to improve, but hopefully I've done enough in this test mini-blockchain project to advance
to the next level :).

### Fun Fact

It is disputed how long exactly baobabs live, but there is a Baobab in South Africa that is 47 m in circumference,
and is said to have been carbon dated at over 6,000 years old ((source)[https://simple.wikipedia.org/wiki/Baobab]).

Thus, alike cutting down a baobab requires enormous effort, so does hacking of a blockchain.