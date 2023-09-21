# Validator Key Generator

Tool to create all needed Validator key files:

Here's how to use it:

```
# install all packages
$ sudo apt update && sudo apt install python3 python3-pip python3-virtualenv

# clone repository
$ git clone https://github.com/iotaledger/validator-key-generator

# enter directory
$ cd validator-key-generator

# execute script
$ ./generate_keys.sh

```

Once executed, you'll find the following files:
`identity.key`: The Hornet identity file
`coo.key`: The Validator signing key
`tendermint.key`: The Tendermint Consensus/Node key
`private.txt`: The private keys in text format
`public.txt`: The public keys in text format

We only require the `public.txt` file from you. Ensure the rest are stored safely and securely. It's crucial not to misplace them.
