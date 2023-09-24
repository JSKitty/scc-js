# SCC.js - A JavaScript SCC implementation written in TypeScript.

SCC.js can be used as an internal factory system to produce Transactions, On-Chain Scripts, Contracts and Signature creation/verification, all without any full node, RPC or cryptography necessary!

For example, [SCP Wallet](https://github.com/stakecube/StakeCubeProtocol) (an Electron-based Lightwallet) uses SCC.js as it's internal wallet system.

# API Documentation

The following docs assume that you've minimally imported the SCC.js library into your Node.js script, e.g:

```js
import * as  SCC = from '@stakecubecoin/scc-js';
// The SCC module exposes two sub-modules, the Wallet and Signer modules
// SCC.wallet
// SCC.signer
```

---

## Wallet (Key Store)

### Generate Wallet (Promise)

Creates a cryptographically-random SCC wallet key pair (Private Key and Public Key)

```js
import * as  SCC = from '@stakecubecoin/scc-js';

// Async
async function newWallet() {
    return await SCC.wallet.generateWallet(); // { 'pubkey': '...', 'privkey': '...' }
}

// Callback
SCC.generateWallet().then(cWallet => {
    // { 'pubkey': '...', 'privkey': '...' }
});
```

### Derive Public Key from Private Key

Derives the public key from an existing WIF-encoded private key.

- Decodes Base58 private keys by default, but can accept raw key bytes with an optional flag.
- Returns a network-encoded, Base58 address by default, but can return a raw Secp256k1 public key with an optional flag.

```js
import * as  SCC = from '@stakecubecoin/scc-js';

// Derive a native base58 SCC address (String)
//                                           Private Key String
const base58Address = SCC.wallet.pubFromPriv('base58_private_key');

// Derive a raw Secp256k1 public key (Uint8Array)
//                                    Private Key String,   fRaw,  fPubBytesOnly
const pubKey = SCC.wallet.pubFromPriv('base58_private_key', false, true);

// Derive a native base58 SCC address (String) from raw private key bytes (Uint8Array)
//                                           Private Key String, fRaw
const base58Address = SCC.wallet.pubFromPriv(uint8PrivKeyBytes,  true);
```

---

## Wallet (Transactions)

`// TODO!`

---

## Signer

### Create Signature (Promise)

Creates a cryptographic signature of a given message, for a given private key.

```js
import * as  SCC = from '@stakecubecoin/scc-js';

// Async
async function signMessage(msg, privkey)) {
    return await SCC.signer.sign(msg, privkey); // Buffer([signature bytes]);
}

// Callback
SCC.signer.sign('hello world', 'WIF_private_key').then(cSig => {
    // Buffer([signature bytes]);
});
```

### Verify Signature (Promise)

Verify the integrity and authorship of a message by it's public key and signature.

```js
import * as  SCC = from '@stakecubecoin/scc-js';

// Async
async function verifyMessage(msg, pubkey, cSig)) {
    return await SCC.signer.verify(msg, pubkey, cSig); // Boolean(true / false)
}

// Callback
SCC.signer.verify(msg, pubkey, cSig).then(fValid => {
    // Boolean(true / false)
});
```
