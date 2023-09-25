/* eslint-disable @typescript-eslint/no-explicit-any */
// Node modules
import crypto from "crypto";
import * as secp256k1 from "@noble/secp256k1";
import * as util from "./util";
import * as wallet from "./wallet";
import * as scripts from "./script";
import BigInteger from "big-integer";

const bitjs: any = {};

/* public vars */
bitjs.pub = (network: "MainNet" | "TestNet" = "MainNet") =>
  util.PUBKEY_ADDRESS[network].toString(16);
bitjs.script = (network: "MainNet" | "TestNet" = "MainNet") =>
  util.SCRIPT_ADDRESS[network].toString(16);
bitjs.priv = (network: "MainNet" | "TestNet" = "MainNet") =>
  util.SECRET_KEY[network].toString(16);
bitjs.compressed = true;
/**
 *
 * @returns
 */
export const transaction = function () {
  const btrx: any = {};
  btrx.version = 2;
  btrx.inputs = [];
  btrx.outputs = [];
  btrx.locktime = 0;
  /**
   *
   * @param txid
   * @param index
   * @param script
   * @param sequence
   * @returns
   */
  btrx.addinput = function (
    txid: string,
    index: number,
    script: string,
    sequence?: number,
  ) {
    const o: any = {};
    o.outpoint = { hash: txid, index: index };
    o.script = Array.from(util.hexStringToByte(script)); // push previous output pubkey script
    o.sequence = sequence || (btrx.locktime == 0 ? 4294967295 : 0);
    return this.inputs.push(o);
  };

  /**
   *
   * @param address
   * @param value
   * @returns
   */
  btrx.addoutput = function (address: string, value: number) {
    const o: any = {};
    let buf: any[] = [];
    const addrDecoded = util.from_b58(address);
    const pubkeyDecoded = Buffer.from(
      addrDecoded.slice(0, addrDecoded.length - 4).slice(1),
    );
    o.value = BigInteger(`${Math.floor(value * 1e8)}`);
    buf.push(scripts.OP.DUP);
    buf.push(scripts.OP.HASH160);
    buf.push(pubkeyDecoded.length);
    buf = buf.concat(Array.from(pubkeyDecoded)); // address in bytes
    buf.push(scripts.OP.EQUALVERIFY);
    buf.push(scripts.OP.CHECKSIG);
    o.script = buf;
    return this.outputs.push(o);
  };
  /**
   *
   * @param value
   * @param data
   * @returns
   */
  btrx.addoutputburn = function (value: number, data: string) {
    const o: any = {};
    o.value = BigInteger(`${Math.floor(value * 1e8)}`);
    o.script = scripts.getScriptForBurn(data);
    return this.outputs.push(o);
  };

  /**
   * Generate the transaction hash to sign from a transaction input
   *
   * @param index
   * @param sigHashType
   * @returns
   */
  btrx.transactionHash = function (index: number, sigHashType: any) {
    // Perform a 'deep clone' by stringifying and re-parsing to obliterate all pointers, then re-assign functions as-needed
    // (I hate that this works)
    const clone = JSON.parse(JSON.stringify(this));
    clone.serialize = this.serialize;
    const shType = sigHashType || 1;
    /* black out all other ins, except this one */
    for (let i = 0; i < clone.inputs.length; i++) {
      if (index != i) {
        clone.inputs[i].script = [];
      }
    }
    if (clone.inputs && clone.inputs[index]) {
      /* SIGHASH : For more info on sig hashs see https://en.bitcoin.it/wiki/OP_CHECKSIG
				and https://bitcoin.org/en/developer-guide#signature-hash-type */
      if (shType == 1) {
        //SIGHASH_ALL 0x01
      } else if (shType == 2) {
        //SIGHASH_NONE 0x02
        clone.outputs = [];
        for (let i = 0; i < clone.inputs.length; i++) {
          if (index != i) {
            clone.inputs[i].sequence = 0;
          }
        }
      } else if (shType == 3) {
        //SIGHASH_SINGLE 0x03
        clone.outputs.length = index + 1;
        for (let i = 0; i < index; i++) {
          clone.outputs[i].value = -1;
          clone.outputs[i].script = [];
        }
        for (let i = 0; i < clone.inputs.length; i++) {
          if (index != i) {
            clone.inputs[i].sequence = 0;
          }
        }
      } else if (shType >= 128) {
        //SIGHASH_ANYONECANPAY 0x80
        clone.inputs = [clone.inputs[index]];
        if (shType == 129) {
          // SIGHASH_ALL + SIGHASH_ANYONECANPAY
        } else if (shType == 130) {
          // SIGHASH_NONE + SIGHASH_ANYONECANPAY
          clone.outputs = [];
        } else if (shType == 131) {
          // SIGHASH_SINGLE + SIGHASH_ANYONECANPAY
          clone.outputs.length = index + 1;
          for (let i = 0; i < index; i++) {
            clone.outputs[i].value = -1;
            clone.outputs[i].script = [];
          }
        }
      }
      let buffer = util.hexStringToByte(clone.serialize());
      buffer = Buffer.from([
        ...buffer,
        ...bitjs.numToBytes(parseInt(shType), 4),
      ]);
      // Hash the transaction with two rounds of SHA256
      const sha256_r1 = crypto.createHash("sha256").update(buffer).digest();
      const sha256_r2 = crypto.createHash("sha256").update(sha256_r1).digest();
      const r = util.byteToHexString(sha256_r2);
      return r;
    } else {
      return false;
    }
  };

  /**
   * Generate a signature from a transaction hash
   *
   * @param index
   * @param wif
   * @param sigHashType
   * @param txhash
   * @returns
   */
  btrx.transactionSig = async function (
    index: number,
    wif: string,
    sigHashType: any,
    txhash: string,
  ) {
    const shType = sigHashType || 1;
    const hash =
      txhash || util.hexStringToByte(this.transactionHash(index, shType));
    if (hash) {
      const bArrConvert = util.from_b58(wif);
      const droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
      const key = droplfour.slice(1, droplfour.length);
      const privkeyBytes = key.slice(0, key.length - 1);
      const sig = await secp256k1.sign(hash, privkeyBytes, {
        canonical: true,
        recovered: true,
      });
      let sigBytes = Buffer.from(sig[0]);
      sigBytes = Buffer.from([
        ...sigBytes,
        ...bitjs.numToVarInt(parseInt(shType, 10)),
      ]);
      return util.byteToHexString(sigBytes);
    } else {
      return false;
    }
  };

  /**
   * Sign a "standard" input
   *
   * @param index
   * @param wif
   * @param sigHashType
   * @returns
   */
  btrx.signinput = async function (
    index: number,
    wif: Uint8Array,
    sigHashType: any,
  ) {
    const pubKey = Buffer.from(wallet.pubFromPriv(wif, false, true));
    const shType = sigHashType || 1;
    const signature = await this.transactionSig(index, wif, shType);
    let buf: any[] = [];
    const sigBytes = util.hexStringToByte(signature);
    buf = [...buf, ...bitjs.numToVarInt(sigBytes.length)];
    buf = [...buf, ...Array.from(sigBytes)];
    buf = [...buf, ...bitjs.numToVarInt(pubKey.length)];
    buf = [...buf, ...Array.from(pubKey)];
    this.inputs[index].script = buf;
    return true;
  };

  /**
   * Sign inputs
   *
   * @param wif
   * @param sigHashType
   * @returns
   */
  btrx.sign = async function (wif: Uint8Array, sigHashType: any) {
    const shType = sigHashType || 1;
    for (let i = 0; i < this.inputs.length; i++) {
      await this.signinput(i, wif, shType);
    }
    return this.serialize();
  };

  /**
   * Serialize a transaction
   *
   * @returns
   */
  btrx.serialize = function () {
    let buffer: any[] = [];
    buffer = [...buffer, ...bitjs.numToBytes(parseInt(this.version), 4)];
    buffer = [...buffer, ...bitjs.numToVarInt(this.inputs.length)];
    for (let i = 0; i < this.inputs.length; i++) {
      const txin = this.inputs[i];
      buffer = [
        ...buffer,
        ...util.hexStringToByte(txin.outpoint.hash).reverse(),
      ];
      buffer = [
        ...buffer,
        ...bitjs.numToBytes(parseInt(txin.outpoint.index), 4),
      ];
      const scriptBytes = txin.script;
      buffer = [...buffer, ...bitjs.numToVarInt(scriptBytes.length)];
      buffer = [...buffer, ...scriptBytes];
      buffer = [...buffer, ...bitjs.numToBytes(parseInt(txin.sequence), 4)];
    }
    buffer = [...buffer, ...bitjs.numToVarInt(this.outputs.length)];
    for (let i = 0; i < this.outputs.length; i++) {
      const txout = this.outputs[i];
      buffer = [...buffer, ...bitjs.numToBytes(txout.value, 8)];
      const scriptBytes = txout.script;
      buffer = [...buffer, ...bitjs.numToVarInt(scriptBytes.length)];
      buffer = [...buffer, ...scriptBytes];
    }
    buffer = [...buffer, ...bitjs.numToBytes(parseInt(this.locktime), 4)];
    return util.byteToHexString(Uint8Array.from(buffer));
  };
  return btrx;
};

/**
 *
 * @param num
 * @param bytes
 * @returns
 */
bitjs.numToBytes = function (num: number, bytes: number) {
  if (typeof bytes === "undefined") bytes = 8;
  if (bytes == 0) {
    return [];
  } else if (num == -1) {
    return Buffer.from("ffffffffffffffff", "hex");
  } else {
    return [num % 256].concat(
      bitjs.numToBytes(Math.floor(num / 256), bytes - 1),
    );
  }
};

/**
 *
 * @param num
 * @returns
 */
bitjs.numToByteArray = function (num: number) {
  if (num <= 256) {
    return [num];
  } else {
    return [num % 256].concat(bitjs.numToByteArray(Math.floor(num / 256)));
  }
};

/**
 *
 * @param num
 * @returns
 */
bitjs.numToVarInt = function (num: number) {
  if (num < 253) {
    return [num];
  } else if (num < 65536) {
    return [253].concat(bitjs.numToBytes(num, 2));
  } else if (num < 4294967296) {
    return [254].concat(bitjs.numToBytes(num, 4));
  } else {
    return [255].concat(bitjs.numToBytes(num, 8));
  }
};

/**
 *
 * @param bytes
 * @returns
 */
bitjs.bytesToNum = function (bytes: string) {
  if (bytes.length == 0) return 0;
  else return bytes[0] + 256 * bitjs.bytesToNum(bytes.slice(1));
};

export default bitjs;
