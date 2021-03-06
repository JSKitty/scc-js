// Require our modules
var SCC = require('./index.js');

async function tests() {
    /* WALLET TESTS */

    // Wallet generation
    console.log("Test 1 --- Wallet Generation");
    let nStartTime = Date.now();
    const cWallet = await SCC.wallet.generateWallet();
    console.log("Priv: " + cWallet.privkey);
    console.log("Pub:  " + cWallet.pubkey);
    console.log("Test 1 --- End (took " + (Date.now() - nStartTime) + " ms)\n\n");

    // Public Derivation
    console.log("Test 2 --- Derive 10 Pubkeys from WIF Privkey");
    nStartTime = Date.now();
    for (let i=0; i<10; ++i) {
        const nKeyStartTime = Date.now();
        const strPubkey = SCC.wallet.pubFromPriv(cWallet.privkey);
        console.log("Pub:  " + strPubkey + ", took " + (Date.now() - nKeyStartTime) + " ms");
    }
    console.log("Test 2 --- End (took " + (Date.now() - nStartTime) + " ms)\n\n");

    // Signature Creation
    console.log('Test 3 --- Create a signature using our test wallet');

    nStartTime = Date.now();
    const cSig = await SCC.signer.sign('test', cWallet.privkey);
    console.log('Sig:  ' + cSig.toString('base64'));
    console.log('Test 3 --- End (took ' + (Date.now() - nStartTime) + ' ms)\n\n');

    // Signature Verification
    console.log('Test 4 --- Verify the signature using only the sig, content and pubkey');

    nStartTime = Date.now();
    const fSigVerif = await SCC.signer.verify('test', cWallet.pubkey, cSig);
    console.log('Verification:  ' + (fSigVerif ? 'Success!' : 'Failed!'));
    console.log('Test 4 --- End (took ' + (Date.now() - nStartTime) + ' ms)');
}

tests();