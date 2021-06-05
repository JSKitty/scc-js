// Require our modules
var wallet = require('./scripts/wallet.js');

async function tests () {
    /* WALLET TESTS */

    // Wallet generation
    console.log("Test 1 --- Wallet Generation");
    let nStartTime = Date.now();
    let cWallet = await wallet.generateWallet();
    console.log("Priv: " + cWallet.privkey);
    console.log("Pub:  " + cWallet.pubkey);
    console.log("Test 1 --- End (took " + (Date.now() - nStartTime) + " ms)\n\n");

    console.log("Test 2 --- Derive Pubkey from WIF Privkey");
    nStartTime = Date.now();
    let strPubkey = await wallet.pubFromPriv(cWallet.privkey);
    console.log("Pub:  " + strPubkey);
    console.log("Test 2 --- End (took " + (Date.now() - nStartTime) + " ms)");
}

tests();