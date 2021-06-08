/* Modules */
const Crypto = require('crypto');
let nsecp256k1 = require('noble-secp256k1');
let getRandomValues = require('get-random-values');
var util = require('./util.js');
var bitjs = require('./bitTrx');

// Pubkey Derivation
pubFromPriv = function (privkey, rawBytes = false) {
	let bArrConvert = rawBytes ? privkey : util.from_b58(privkey);
	let droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
	let key = droplfour.slice(1, droplfour.length);
	let privkeyBytes = key.slice(0, key.length - 1);
	const pubkeyExt = nsecp256k1.getPublicKey(privkeyBytes);
	let pubHash = Crypto.createHash("sha256").update(pubkeyExt).digest('hex');
	let pubHashRMD160 = Crypto.createHash("ripemd160").update(util.hexStringToByte(pubHash)).digest('hex');
	let pubHashNetwork = util.PUBKEY_ADDRESS.toString(16) + pubHashRMD160;
	let pubHash2 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHashNetwork)).digest('hex');
	let pubHash3 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHash2)).digest('hex').toUpperCase();
	let chcksumPub = String(pubHash3).substr(0, 8).toUpperCase();
	let pubPreBase = pubHashNetwork + chcksumPub;
	let pubKey = util.to_b58(util.hexStringToByte(pubPreBase));
	//console.log("Type: " + (rawBytes ? "raw" : "wif") + ", Pub: " + pubKey);
	return pubKey;
}

// Wallet Generation
generateWallet = async function (strPrefix = false) {
	// Private Key Generation
	let randBytes = getRandomValues(new Uint8Array(32));
	let privHex = util.byteToHexString(randBytes).toUpperCase();
	let privWithVersion = util.SECRET_KEY.toString(16) + privHex + "01";
	let privHash1 = Crypto.createHash("sha256").update(util.hexStringToByte(privWithVersion)).digest('hex');
	let privHash2 = Crypto.createHash("sha256").update(util.hexStringToByte(privHash1)).digest('hex').toUpperCase();
	let chcksum = String(privHash2).substr(0, 8).toUpperCase();
	let keyWithChcksum = privWithVersion + chcksum;
	let privkeyBytes = util.hexStringToByte(keyWithChcksum);
	let privkeyWIF = util.to_b58(privkeyBytes);
	// Derive the public key
	let pubKey = await pubFromPriv(privkeyBytes, true);
	//console.log("Public Key:     " + pubKey);

	// TODO: If vanity search (strPrefix) is supplied, we need to loop until we get the correct key set
	let ret = {
		pubkey: null,
		privkey: null,
		vanity_match: false
	}
	if (strPrefix === false || (strPrefix !== false && pubKey.toLowerCase().startsWith(strPrefix))) {
		ret.pubkey = pubKey;
		ret.privkey = privkeyWIF;
		ret.vanity_match = true;
	}
	return ret;
}

exports.tx             = bitjs;
exports.generateWallet = generateWallet;
exports.pubFromPriv    = pubFromPriv;