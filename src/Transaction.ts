import crypto from "crypto";
import bit from "./bit";
import * as util from "./util";
import * as wallet from "./wallet";
import * as scripts from "./script";
import BigInteger from "big-integer";
import * as secp256k1 from "@noble/secp256k1";
import { TransactionInput as input } from "./interface/TransactionInput";
import { TransactionOutput as output } from "./interface/TransactionOutput";

export class Transaction {
  /**
   *
   * @param version
   * @param inputs
   * @param outputs
   * @param locktime
   */
  constructor(
    public version: number = 2,
    public inputs: input[] = [],
    public outputs: output[] = [],
    public locktime: number = 0,
  ) {}

  /**
   *
   * @param txid
   * @param index
   * @param script
   * @param sequence
   * @returns
   */
  addinput = (
    txid: string,
    index: number,
    script: string,
    sequence?: number,
  ) => {
    const input: input = {
      outpoint: { hash: txid, index: index },
      script: Array.from(util.hexStringToByte(script)), // push previous output pubkey script
      sequence: sequence || (this.locktime == 0 ? 4294967295 : 0),
    };
    return this.inputs.push(input);
  };

  /**
   *
   * @param address
   * @param value
   * @returns
   */
  addoutput = (address: string, value: number) => {
    let buf: number[] = [];
    const addrDecoded = util.from_b58(address);
    const pubkeyDecoded = Buffer.from(
      addrDecoded.slice(0, addrDecoded.length - 4).slice(1),
    );
    buf.push(scripts.OP.DUP);
    buf.push(scripts.OP.HASH160);
    buf.push(pubkeyDecoded.length);
    buf = buf.concat(Array.from(pubkeyDecoded)); // address in bytes
    buf.push(scripts.OP.EQUALVERIFY);
    buf.push(scripts.OP.CHECKSIG);
    const output: output = {
      value: BigInteger(`${Math.floor(value * 1e8)}`),
      script: buf,
    };
    return this.outputs.push(output);
  };

  /**
   *
   * @param value
   * @param data
   * @returns
   */
  addoutputburn = (value: number, data: string) => {
    const output: output = {
      value: BigInteger(`${Math.floor(value * 1e8)}`),
      script: scripts.getScriptForBurn(data),
    };
    return this.outputs.push(output);
  };

  /**
   *
   * @param index
   * @param sigHashType
   * @returns
   */
  transactionHash = (index: number, sigHashType?: number) => {
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
        ...bit.numToBytes(parseInt(`${shType}`), 4),
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
   *
   * @param index
   * @param wif
   * @param sigHashType
   * @param txhash
   * @returns
   */
  transactionSig = async (
    index: number,
    wif: Uint8Array,
    sigHashType?: number,
    txhash?: string,
  ) => {
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
        ...bit.numToVarInt(parseInt(`${shType}`, 10)),
      ]);
      return util.byteToHexString(sigBytes);
    } else {
      return false;
    }
  };

  /**
   *
   * @param index
   * @param wif
   * @param sigHashType
   * @returns
   */
  signinput = async (index: number, wif: Uint8Array, sigHashType?: number) => {
    const pubKey = Buffer.from(wallet.pubFromPriv(wif, false, true));
    const shType = sigHashType || 1;
    const signature = await this.transactionSig(index, wif, shType);
    let buf: number[] = [];
    const sigBytes = util.hexStringToByte(signature);
    buf = [...buf, ...bit.numToVarInt(sigBytes.length)];
    buf = [...buf, ...Array.from(sigBytes)];
    buf = [...buf, ...bit.numToVarInt(pubKey.length)];
    buf = [...buf, ...Array.from(pubKey)];
    this.inputs[index].script = buf;
    return true;
  };

  /**
   *
   * @param wif
   * @param sigHashType
   * @returns
   */
  sign = async (wif: Uint8Array, sigHashType?: number) => {
    const shType = sigHashType || 1;
    for (let i = 0; i < this.inputs.length; i++) {
      await this.signinput(i, wif, shType);
    }
    return this.serialize();
  };

  serialize = () => {
    let buffer: number[] = [];
    buffer = [...buffer, ...bit.numToBytes(parseInt(`${this.version}`), 4)];
    buffer = [...buffer, ...bit.numToVarInt(this.inputs.length)];
    for (let i = 0; i < this.inputs.length; i++) {
      const txin = this.inputs[i];
      buffer = [
        ...buffer,
        ...util.hexStringToByte(txin.outpoint.hash).reverse(),
      ];
      buffer = [
        ...buffer,
        ...bit.numToBytes(parseInt(`${txin.outpoint.index}`), 4),
      ];
      const scriptBytes = txin.script;
      buffer = [...buffer, ...bit.numToVarInt(scriptBytes.length)];
      buffer = [...buffer, ...scriptBytes];
      buffer = [...buffer, ...bit.numToBytes(parseInt(`${txin.sequence}`), 4)];
    }
    buffer = [...buffer, ...bit.numToVarInt(this.outputs.length)];
    for (let i = 0; i < this.outputs.length; i++) {
      const txout = this.outputs[i];
      buffer = [...buffer, ...bit.numToBytes(Number(txout.value), 8)];
      const scriptBytes = txout.script;
      buffer = [...buffer, ...bit.numToVarInt(scriptBytes.length)];
      buffer = [...buffer, ...scriptBytes];
    }
    buffer = [...buffer, ...bit.numToBytes(parseInt(`${this.locktime}`), 4)];
    return util.byteToHexString(Uint8Array.from(buffer));
  };
}

export const transaction = (
  version: number = 2,
  inputs: input[] = [],
  outputs: output[] = [],
  locktime: number = 0,
) => {
  return new Transaction(version, inputs, outputs, locktime);
};

export { input, output };
