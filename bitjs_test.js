// Require our modules
var wallet = require('./scripts/wallet.js');

// This is a mainnet wallet with (a TINY amount of) real funds on it, hopefully Luke can make use of this easily!
// Open: "https://stakecubecoin.net/web3/submittx?tx=<serialized_hex_here>" to submit the output from `cTx.sign()`
// The above node will publish the TX and return a TX-ID IF successful, otherwise it'll just return "error" or smth.

let pub  = "sRNq5edCiP5x6Cnucmz7UHtQotKCrBATDR";
let priv = "eZJbJgGXGTY4K9ktbPCAw7N8jdSrrQCoaxwhh1wzFDT8BsHwjipJ";

let cTx = new wallet.tx.transaction();
cTx.addinput("9e15bce6268c54901f47142c6128d925d00a332a7040dc16a1752e298567caf3", // TX-ID
             0,                                                                  // Index (vout)
             "76a9144e30a9894c3885ca7dff18ed1627447f9bad559a88ac");              // Script Pubkey
cTx.addoutput(pub, 0.005);
cTx.addoutput(pub, 0.004);
// balance: 0.01
// send: 0.005
// change: 0.004
// fee: 0.001
console.log(cTx.sign(priv, 1));
// This is logging a pretty small serialized transaction, which cannot be decoded by the Core wallet.
// So something is probably wrong during the signing process!