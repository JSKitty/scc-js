/* Modules */
const Crypto = require('crypto');
const nsecp256k1 = require('@noble/secp256k1');
var util = require('./util.js');
var bitjs = require('./bitTrx');

const ERRS = {
	BAD_KEYLEN:   "Invalid key length or malformed base58 encoding",
	BAD_PREFIX:   "Invalid key byte, expected " + util.PUBKEY_ADDRESS,
	BAD_CHECKSUM: "Invalid key checksum"
}
Object.freeze(ERRS);

// Verify integrity of a network pubkey
verifyPubkey = function (strPubkey = "") {
	// Decode base58 and verify basic integrity
	const strDecoded = util.from_b58(strPubkey);
	if (strDecoded.length !== 25)              throw new Error(ERRS.BAD_KEYLEN);
	if (strDecoded[0] !== util.PUBKEY_ADDRESS) throw new Error(ERRS.BAD_PREFIX);

	// Sha256d hash the pubkey payload
	const pubHash1 = Crypto.createHash("sha256").update(strDecoded.slice(0, 21)).digest();
	const pubHash2 = Crypto.createHash("sha256").update(pubHash1).digest();

	// Verify payload integrity via checksum
	if (pubHash2.subarray(0, 4).compare(strDecoded.slice(21, 25)) !== 0) throw new Error(ERRS.BAD_CHECKSUM);

	// All is valid! (base58 format, payload and checksum integrity)
	return true;
}

// (network) Pubkey Derivation from Secp256k1 private key
netPubFromSecpPub = function (secpPubkey) {
	const pubHash = Crypto.createHash("sha256").update(secpPubkey).digest('hex');
	const pubHashRMD160 = Crypto.createHash("ripemd160").update(util.hexStringToByte(pubHash)).digest('hex');
	const pubHashNetwork = util.PUBKEY_ADDRESS.toString(16) + pubHashRMD160;
	const pubHash2 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHashNetwork)).digest('hex');
	const pubHash3 = Crypto.createHash("sha256").update(util.hexStringToByte(pubHash2)).digest('hex').toUpperCase();
	const chcksumPub = String(pubHash3).substring(0, 8).toUpperCase();
	const pubPreBase = pubHashNetwork + chcksumPub;
	// Return the Network-Encoded pubkey (SCC address)
	return util.to_b58(util.hexStringToByte(pubPreBase));
}

// (network) Pubkey Derivation from (network) private key (WIF)
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
generateWallet = async function () {
	// Private Key Generation
	const randBytes = Crypto.randomBytes(32);
	const privHex = util.byteToHexString(randBytes).toUpperCase();
	const privWithVersion = util.SECRET_KEY.toString(16) + privHex + "01";
	const privHash1 = Crypto.createHash("sha256").update(util.hexStringToByte(privWithVersion)).digest('hex');
	const privHash2 = Crypto.createHash("sha256").update(util.hexStringToByte(privHash1)).digest('hex').toUpperCase();
	const chcksum = String(privHash2).substring(0, 8).toUpperCase();
	const keyWithChcksum = privWithVersion + chcksum;
	const privkeyBytes = util.hexStringToByte(keyWithChcksum);
	const privkeyWIF = util.to_b58(privkeyBytes);

	// Derive the public key
	const pubKey = await pubFromPriv(privkeyBytes, true);

	// Return wallet object
	return {
		'pubkey': pubKey,
		'privkey': privkeyWIF
	};
}

exports.tx                = bitjs;
exports.generateWallet    = generateWallet;
exports.pubFromPriv       = pubFromPriv;
exports.netPubFromSecpPub = netPubFromSecpPub;
exports.verifyPubkey      = verifyPubkey;