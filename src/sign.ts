/* eslint-disable @typescript-eslint/no-explicit-any */
import * as secp256k1 from "@noble/secp256k1";
import crypto from "crypto";
import * as util from "./util";
import * as wallet from "./wallet";
import * as varuint from "./varuint";

/**
 *
 * @param b
 * @returns
 */
function sha256(b: Buffer) {
  return crypto.createHash("sha256").update(b).digest();
}

/**
 *
 * @param buffer
 * @returns
 */
function hash256(buffer: Buffer) {
  return sha256(sha256(buffer));
}

/**
 *
 * @param signature
 * @param recovery
 * @param compressed
 * @returns
 */
function encodeSignature(
  signature: Uint8Array,
  recovery: number,
  compressed: boolean | undefined,
) {
  if (compressed) recovery += 4;
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature]);
}

/**
 *
 * @param buffer
 * @returns
 */
function decodeSignature(buffer: Buffer) {
  if (buffer.length !== 65) throw new Error("Invalid signature length");

  const flagByte = buffer.readUInt8(0) - 27;
  if (flagByte > 15 || flagByte < 0) {
    throw new Error("Invalid signature parameter");
  }

  return {
    compressed: !!(flagByte & 12),
    recovery: flagByte & 3,
    signature: buffer.slice(1),
  };
}

/**
 *
 * @param message
 * @param messagePrefix
 * @returns
 */
function magicHash(
  message: string | Buffer,
  messagePrefix: string | Buffer | undefined,
) {
  messagePrefix = messagePrefix || "\x19DarkCoin Signed Message:\n";
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, "utf8");
  }
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, "utf8");
  }
  const messageVISize = varuint.encodingLength(message.length);
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length,
  );
  Buffer.from(messagePrefix).copy(buffer, 0);
  varuint.encode(message.length, buffer, messagePrefix.length);
  message.copy(buffer, messagePrefix.length + messageVISize);
  return hash256(buffer);
}

/**
 *
 * @param messagePrefixArg
 * @param sigOptions
 * @returns
 */
function prepareSign(
  messagePrefixArg: string | Buffer | undefined,
  sigOptions: any,
) {
  let prefixArg: string | Buffer | undefined = messagePrefixArg;
  if (typeof messagePrefixArg === "object" && sigOptions === undefined) {
    sigOptions = messagePrefixArg;
    prefixArg = undefined;
  }
  const { extraEntropy } = sigOptions || { extraEntropy: true };
  return {
    prefixArg,
    extraEntropy,
  };
}

/**
 *
 * @param message
 * @param privateKey
 * @param compressed
 * @param messagePrefix
 * @param sigOptions
 * @returns
 */
async function sign(
  message: string,
  privateKey: string,
  compressed?: boolean,
  messagePrefix?: string | Buffer,
  sigOptions?: any,
) {
  const { prefixArg, extraEntropy } = prepareSign(messagePrefix, sigOptions);
  const hash = magicHash(message, prefixArg);

  const privateKeyBytes = util.wifToBytes(privateKey);
  // Default 'compressed' to true
  if (compressed === undefined) compressed = true;

  // extraEntropy will also default to 'true' if left unset
  return secp256k1
    .sign(hash, privateKeyBytes, {
      recovered: true,
      der: false,
      extraEntropy: extraEntropy as Uint8Array | string | true,
    })
    .then(function (result) {
      return encodeSignature(result[0], result[1], compressed);
    });
}

/**
 *
 * @param message
 * @param address
 * @param signature
 * @param messagePrefix
 * @returns
 */
function verify(
  message: string,
  address: string | Uint8Array,
  signature: string | Buffer,
  messagePrefix?: string | Buffer,
  network: "MainNet" | "TestNet" = "MainNet",
) {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, "base64");

  const parsed = decodeSignature(signature);

  const hash = magicHash(message, messagePrefix);
  const publicKey = secp256k1.recoverPublicKey(
    hash,
    parsed.signature,
    parsed.recovery,
    parsed.compressed,
  );

  return address === wallet.netPubFromSecpPub(publicKey, network);
}

export { magicHash, sign, verify };
