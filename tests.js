// Require our modules
var scc = require('./index.js');

async function tests () {
    /* WALLET TESTS */

    // Wallet generation
    console.log("Test 1 --- Wallet Generation");
    let nStartTime = Date.now();
    let cWallet = await scc.generateWallet();
    console.log("Priv: " + cWallet.privkey);
    console.log("Pub:  " + cWallet.pubkey);
    console.log("Test 1 --- End (took " + (Date.now() - nStartTime) + " ms)\n\n");

    console.log("Test 2 --- Derive 10 Pubkeys from WIF Privkey");
    nStartTime = Date.now();
    for (let i=0; i<10; i++) {
        let nKeyStartTime = Date.now();
        let strPubkey = await scc.pubFromPriv(cWallet.privkey);
        console.log("Pub:  " + strPubkey + ", took " + (Date.now() - nKeyStartTime) + " ms");
    }
    console.log("Test 2 --- End (took " + (Date.now() - nStartTime) + " ms)");
}

tests();