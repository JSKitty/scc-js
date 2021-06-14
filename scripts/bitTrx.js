// Node modules
const Crypto = require('crypto');
var BigInteger = require("big-integer");
let nsecp256k1 = require('noble-secp256k1');

// In-house libs
var util = require('./util.js');
var wallet = require('./wallet.js');
var scripts = require("./script.js");

var bitjs = function () { };

/* public vars */
bitjs.pub    = util.PUBKEY_ADDRESS.toString(16);
bitjs.script = util.SCRIPT_ADDRESS.toString(16);
bitjs.priv   = util.SECRET_KEY.toString(16);
bitjs.compressed = true;
exports.transaction = function() {
	var btrx = {};
	btrx.version = 2;
	btrx.inputs = [];
	btrx.outputs = [];
	btrx.locktime = 0;
	btrx.addinput = function(txid, index, script, sequence) {
		var o = {};
		o.outpoint = {'hash': txid, 'index': index};
		o.script = Array.from(util.hexStringToByte(script)); // push previous output pubkey script
		o.sequence = sequence || ((btrx.locktime == 0) ? 4294967295 : 0);
		return this.inputs.push(o);
	}
	btrx.addoutput = function(address, value) {
		var o = {};
		var buf = [];
		var addrDecoded = util.from_b58(address);
		var pubkeyDecoded = addrDecoded.slice(0, addrDecoded.length - 4).slice(1);
		o.value = new BigInteger('' + Math.round((value * 1) * 1e8), 10);
		buf.push(scripts.OP.DUP);
		buf.push(scripts.OP.HASH160);
		buf.push(pubkeyDecoded.length);
		buf = buf.concat(Array.from(pubkeyDecoded)); // address in bytes
		buf.push(scripts.OP.EQUALVERIFY);
		buf.push(scripts.OP.CHECKSIG);
		o.script = buf;
		return this.outputs.push(o);		
	}
	btrx.addoutputburn = function(value, data) {
		var o = {};
		o.value = new BigInteger('' + Math.round((value * 1) * 1e8), 10);
		o.script = getScriptForBurn(data);
		return this.outputs.push(o);
	}
	/* generate the transaction hash to sign from a transaction input */
	btrx.transactionHash = function(index, sigHashType) {
		var clone = bitjs.clone(this);
		var shType = sigHashType || 1;
		/* black out all other ins, except this one */
		for (var i = 0; i < clone.inputs.length; i++) {
			if(index!=i){
				clone.inputs[i].script = [];
			}
		}
		if((clone.inputs) && clone.inputs[index]){
			/* SIGHASH : For more info on sig hashs see https://en.bitcoin.it/wiki/OP_CHECKSIG
				and https://bitcoin.org/en/developer-guide#signature-hash-type */
			if(shType == 1){
				//SIGHASH_ALL 0x01
			} else if(shType == 2){
				//SIGHASH_NONE 0x02
				clone.outputs = [];
				for (var i = 0; i < clone.inputs.length; i++) {
					if(index!=i){
						clone.inputs[i].sequence = 0;
					}
				}
			} else if(shType == 3){
				//SIGHASH_SINGLE 0x03
				clone.outputs.length = index + 1;
				for(var i = 0; i < index; i++){
					clone.outputs[i].value = -1;
					clone.outputs[i].script = [];
				}
				for (var i = 0; i < clone.inputs.length; i++) {
					if(index!=i){
						clone.inputs[i].sequence = 0;
					}
				}
			} else if (shType >= 128){
				//SIGHASH_ANYONECANPAY 0x80
				clone.inputs = [clone.inputs[index]];
				if(shType==129){
					// SIGHASH_ALL + SIGHASH_ANYONECANPAY
				} else if(shType==130){
					// SIGHASH_NONE + SIGHASH_ANYONECANPAY
					clone.outputs = [];
				} else if(shType==131){
											// SIGHASH_SINGLE + SIGHASH_ANYONECANPAY
					clone.outputs.length = index + 1;
					for(var i = 0; i < index; i++){
						clone.outputs[i].value = -1;
						clone.outputs[i].script = [];
					}
				}
			}
			var buffer = util.hexStringToByte(clone.serialize());
			buffer = Buffer.from([...buffer, ...bitjs.numToBytes(parseInt(shType), 4)]);
			// Hash the transaction with two rounds of SHA256
			var sha256_r1 = Crypto.createHash('sha256').update(buffer).digest();
			var sha256_r2 = Crypto.createHash('sha256').update(sha256_r1).digest();
			var r = util.byteToHexString(sha256_r2);
			return r;
		} else {
			return false;
		}
	}
	/* generate a signature from a transaction hash */
	btrx.transactionSig = async function(index, wif, sigHashType, txhash) {
		var shType = sigHashType || 1;
		var hash = txhash || util.hexStringToByte(this.transactionHash(index, shType));
		if (hash) {
			let bArrConvert = util.from_b58(wif);
			let droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
			let key = droplfour.slice(1, droplfour.length);
			let privkeyBytes = key.slice(0, key.length - 1);
			const sig = await nsecp256k1.sign(hash, privkeyBytes, { canonical: true, recovered: true });
			var sigBytes = Buffer.from(sig[0]);
			sigBytes = [...sigBytes, ...bitjs.numToVarInt(parseInt(shType, 10))];
			return util.byteToHexString(sigBytes);
		} else {
			return false;
		}
	}
	/* sign a "standard" input */
	btrx.signinput = async function(index, wif, sigHashType) {
		let pubKey = wallet.pubFromPriv(wif, false, true);
		var shType = sigHashType || 1;
		var signature = await this.transactionSig(index, wif, shType);
		var buf = [];
		var sigBytes = util.hexStringToByte(signature);
		buf = [...buf, ...bitjs.numToVarInt(sigBytes.length)];
		buf = [...buf, ...Array.from(sigBytes)];
		buf = [...buf, ...bitjs.numToVarInt(pubKey.length)];
		buf = [...buf, ...Array.from(pubKey)];
		this.inputs[index].script = buf;
		return true;
	}
	/* sign inputs */
	btrx.sign = async function(wif, sigHashType) {
		var shType = sigHashType || 1;
		for (var i = 0; i < this.inputs.length; i++) {
			await this.signinput(i, wif, shType);
		}
		return this.serialize();
	}
	/* serialize a transaction */
	btrx.serialize = function() {
		var buffer = [];
		buffer = [...buffer, ...(bitjs.numToBytes(parseInt(this.version), 4))];
		buffer = [...buffer, ...(bitjs.numToVarInt(this.inputs.length))];
		for (var i = 0; i < this.inputs.length; i++) {
			var txin = this.inputs[i];		
			buffer = [...buffer, ...(util.hexStringToByte(txin.outpoint.hash).reverse())];
			buffer = [...buffer, ...(bitjs.numToBytes(parseInt(txin.outpoint.index), 4))];
			var scriptBytes = txin.script;
			buffer = [...buffer, ...(bitjs.numToVarInt(scriptBytes.length))];
			buffer = [...buffer, ...(scriptBytes)];
			buffer = [...buffer, ...(bitjs.numToBytes(parseInt(txin.sequence), 4))];
		}		
		buffer = [...buffer, ...bitjs.numToVarInt(this.outputs.length)];
		for (var i = 0; i < this.outputs.length; i++) {
			var txout = this.outputs[i];			
			buffer = [...buffer, ...bitjs.numToBytes(txout.value, 8)];
			var scriptBytes = txout.script;			
			buffer = [...buffer, ...bitjs.numToVarInt(scriptBytes.length)];
			buffer = [...buffer, ...scriptBytes];
		}		
		buffer = [...buffer, ...bitjs.numToBytes(parseInt(this.locktime), 4)];
		return util.byteToHexString(buffer);
	}
	return btrx;
}
bitjs.numToBytes = function(num, bytes) {
	if (typeof bytes === "undefined") bytes = 8;
	if (bytes == 0) {
		return [];
	} else if (num == -1){
		return Crypto.util.hexToBytes("ffffffffffffffff");
	} else {
		return [num % 256].concat(bitjs.numToBytes(Math.floor(num / 256), bytes - 1));
	}
}
bitjs.numToByteArray = function(num) {
	if (num <= 256) {
		return [num];
	} else {
		return [num % 256].concat(bitjs.numToByteArray(Math.floor(num / 256)));
	}
}
bitjs.numToVarInt = function(num) {
	if (num < 253) {
		return [num];
	} else if (num < 65536) {
		return [253].concat(bitjs.numToBytes(num, 2));
	} else if (num < 4294967296) {
		return [254].concat(bitjs.numToBytes(num, 4));
	} else {
		return [255].concat(bitjs.numToBytes(num, 8));
	}
}
bitjs.bytesToNum = function(bytes) {
	if (bytes.length == 0) return 0;
	else return bytes[0] + 256 * bitjs.bytesToNum(bytes.slice(1));
}
bitjs.clone = function (x)
{
    if (x === null || x === undefined)
        return x;
    if (typeof x.clone === "function")
        return x.clone();
    if (x.constructor == Array)
    {
        var r = [];
        for (var i=0,n=x.length; i<n; i++)
            r.push(clone(x[i]));
        return r;
    }
    return x;
}
return bitjs;