/* Modules */
const Crypto = require('crypto');
const nsecp256k1 = require('@noble/secp256k1');
const getRandomValues = require('get-random-values');
var util = require('./util.js');
var bitjs = require('./bitTrx');

netPubFromSecpPub = function (secpPubkey) {
	const pubHash = Crypto.createHash("sha256").update(secpPubkey).digest('hex');
	const pubHashRMD160 = Crypto.createHash("ripemd160").update(util.hexStringToByte(pubHash)).digest('hex');
	const pubHashNetwork = util.PUBKEY_ADDRESS.toString(16) + pubHashRMD160;
	const pubHash2 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHashNetwork)).digest('hex');
	const pubHash3 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHash2)).digest('hex').toUpperCase();
	const chcksumPub = String(pubHash3).substr(0, 8).toUpperCase();
	const pubPreBase = pubHashNetwork + chcksumPub;
	// Return the Network-Encoded pubkey (SCC address)
	return util.to_b58(util.hexStringToByte(pubPreBase));
}

// Pubkey Derivation
pubFromPriv = function (privkey, rawBytes = false, pubBytesOnly = false) {
	const bArrConvert = rawBytes ? privkey : util.from_b58(privkey);
	const droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
	const key = droplfour.slice(1, droplfour.length);
	const privkeyBytes = key.slice(0, key.length - 1);
	const pubkeyExt = nsecp256k1.getPublicKey(privkeyBytes, true);
	if (pubBytesOnly) return pubkeyExt;
	return netPubFromSecpPub(pubkeyExt);
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

exports.tx                = bitjs;
exports.generateWallet    = generateWallet;
exports.pubFromPriv       = pubFromPriv;
exports.netPubFromSecpPub = netPubFromSecpPub;