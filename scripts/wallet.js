/* Modules */
const Crypto = require('crypto');
const secp256k1 = require('secp256k1');
let getRandomValues = require('get-random-values');

/* chainparams */
const PUBKEY_ADDRESS = 125;
const SCRIPT_ADDRESS = 117;
const SECRET_KEY     = 253;

// ByteToHexString Convertions
function byteToHexString(uint8arr) {
	if (!uint8arr) {
		return '';
	}
	var hexStr = '';
	for (var i = 0; i < uint8arr.length; i++) {
		var hex = (uint8arr[i] & 0xff).toString(16);
		hex = (hex.length === 1) ? '0' + hex : hex;
		hexStr += hex;
	}
	return hexStr.toUpperCase();
}
function hexStringToByte(str) {
	if (!str) {
		return new Uint8Array();
	}
	var a = [];
	for (var i = 0, len = str.length; i < len; i += 2) {
		a.push(parseInt(str.substr(i, 2), 16));
	}
	return new Uint8Array(a);
}

var MAP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; // B58 Encoding Map
//B58 Encoding
var to_b58 = function (
	B,             // Uint8Array raw byte input
	A              // Base58 characters (i.e. "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
) {
	var d = [],    // the array for storing the stream of base58 digits
		s = "",    // the result string variable that will be returned
		i,         // the iterator variable for the byte input
		j,         // the iterator variable for the base58 digit array (d)
		c,         // the carry amount variable that is used to overflow from the current base58 digit to the next base58 digit
		n;         // a temporary placeholder variable for the current base58 digit
	for (i in B) { // loop through each byte in the input stream
		j = 0,                           // reset the base58 digit iterator
			c = B[i];                    // set the initial carry amount equal to the current byte amount
		s += c || s.length ^ i ? "" : 1; // prepend the result string with a "1" (0 in base58) if the byte stream is zero and non-zero bytes haven't been seen yet (to ensure correct decode length)
		while (j in d || c) {            // start looping through the digits until there are no more digits and no carry amount
			n = d[j];                    // set the placeholder for the current base58 digit
			n = n ? n * 256 + c : c;     // shift the current base58 one byte and add the carry amount (or just add the carry amount if this is a new digit)
			c = n / 58 | 0;              // find the new carry amount (floored integer of current digit divided by 58)
			d[j] = n % 58;               // reset the current base58 digit to the remainder (the carry amount will pass on the overflow)
			j++                          // iterate to the next base58 digit
		}
	}
	while (j--)       // since the base58 digits are backwards, loop through them in reverse order
		s += A[d[j]]; // lookup the character associated with each base58 digit
	return s          // return the final base58 string
}
//B58 Decoding
var from_b58 = function (
	S,             // Base58 encoded string input
	A              // Base58 characters (i.e. "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
) {
	var d = [],    // the array for storing the stream of decoded bytes
		b = [],    // the result byte array that will be returned
		i,         // the iterator variable for the base58 string
		j,         // the iterator variable for the byte array (d)
		c,         // the carry amount variable that is used to overflow from the current byte to the next byte
		n;         // a temporary placeholder variable for the current byte
	for (i in S) { // loop through each base58 character in the input string
		j = 0,                             // reset the byte iterator
			c = A.indexOf(S[i]);           // set the initial carry amount equal to the current base58 digit
		if (c < 0)                         // see if the base58 digit lookup is invalid (-1)
			return undefined;              // if invalid base58 digit, bail out and return undefined
		c || b.length ^ i ? i : b.push(0); // prepend the result array with a zero if the base58 digit is zero and non-zero characters haven't been seen yet (to ensure correct decode length)
		while (j in d || c) {              // start looping through the bytes until there are no more bytes and no carry amount
			n = d[j];                      // set the placeholder for the current byte
			n = n ? n * 58 + c : c;        // shift the current byte 58 units and add the carry amount (or just add the carry amount if this is a new byte)
			c = n >> 8;                    // find the new carry amount (1-byte shift of current byte value)
			d[j] = n % 256;                // reset the current byte to the remainder (the carry amount will pass on the overflow)
			j++                            // iterate to the next byte
		}
	}
	while (j--)               // since the byte array is backwards, loop through it in reverse order
		b.push(d[j]);         // append each byte to the result
	return new Uint8Array(b)  // return the final byte array in Uint8Array format
}

// Pubkey Derivation
pubFromPriv = async function (privkey, rawBytes = false) {
	let bArrConvert = rawBytes ? privkey : from_b58(privkey, MAP);
	let droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
	let key = droplfour.slice(1, droplfour.length);
	let privkeyBytes = key.slice(0, key.length - 1);
	const pubkeyExt = secp256k1.publicKeyCreate(privkeyBytes);
	let pubHash = Crypto.createHash("sha256").update(pubkeyExt).digest('hex');
	let pubHashRMD160 = Crypto.createHash("ripemd160").update(hexStringToByte(pubHash)).digest('hex');
	let pubHashNetwork = PUBKEY_ADDRESS.toString(16) + pubHashRMD160;
	let pubHash2 = Crypto.createHash("sha256").update(hexStringToByte(pubHashNetwork)).digest('hex');
	let pubHash3 = Crypto.createHash("sha256").update(hexStringToByte(pubHash2)).digest('hex').toUpperCase();
	let chcksumPub = String(pubHash3).substr(0, 8).toUpperCase();
	let pubPreBase = pubHashNetwork + chcksumPub;
	let pubKey = to_b58(hexStringToByte(pubPreBase), MAP);
	//console.log("Type: " + (rawBytes ? "raw" : "wif") + ", Pub: " + pubKey);
	return pubKey;
}

// Wallet Generation
generateWallet = async function (strPrefix = false) {
	// Private Key Generation
	let randBytes = getRandomValues(new Uint8Array(32));
	let privHex = byteToHexString(randBytes).toUpperCase();
	let privWithVersion = SECRET_KEY.toString(16) + privHex + "01";
	let privHash1 = Crypto.createHash("sha256").update(hexStringToByte(privWithVersion)).digest('hex');
	let privHash2 = Crypto.createHash("sha256").update(hexStringToByte(privHash1)).digest('hex').toUpperCase();
	let chcksum = String(privHash2).substr(0, 8).toUpperCase();
	let keyWithChcksum = privWithVersion + chcksum;
	let privkeyBytes = hexStringToByte(keyWithChcksum);
	let privkeyWIF = to_b58(privkeyBytes, MAP);
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


exports.generateWallet = generateWallet;
exports.pubFromPriv    = pubFromPriv;