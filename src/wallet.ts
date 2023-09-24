/* eslint-disable @typescript-eslint/no-explicit-any */
/* Modules */
import crypto from "crypto";
import * as secp256k1 from "@noble/secp256k1";
import * as util from "./util";
import * as tx from "./bitTrx";

const ERRS = (network: "MainNet" | "TestNet" = "MainNet") => {
  return {
    BAD_KEYLEN: `Invalid key length or malformed base58 encoding`,
    BAD_PREFIX: `Invalid key byte, expected ${util.PUBKEY_ADDRESS[network]}`,
    BAD_CHECKSUM: `Invalid key checksum`,
  };
};
Object.freeze(ERRS);

/**
 * Verify integrity of a network pubkey
 *
 * @param strPubkey
 * @returns
 */
export const verifyPubkey = function (
  strPubkey = "",
  network: "MainNet" | "TestNet" = "MainNet",
) {
  // Decode base58 and verify basic integrity
  const strDecoded = util.from_b58(strPubkey);
  if (strDecoded.length !== 25) throw new Error(ERRS(network).BAD_KEYLEN);
  if (strDecoded[0] !== util.PUBKEY_ADDRESS[network])
    throw new Error(ERRS(network).BAD_PREFIX);

  // Sha256d hash the pubkey payload
  const pubHash1 = crypto
    .createHash("sha256")
    .update(strDecoded.slice(0, 21))
    .digest();
  const pubHash2 = crypto.createHash("sha256").update(pubHash1).digest();

  // Verify payload integrity via checksum
  if (
    pubHash2.subarray(0, 4).compare(Buffer.from(strDecoded.slice(21, 25))) !== 0
  )
    throw new Error(ERRS(network).BAD_CHECKSUM);

  // All is valid! (base58 format, payload and checksum integrity)
  return true;
};

/**
 * (network) Pubkey Derivation from Secp256k1 private key
 *
 * @param secpPubkey
 * @returns
 */
export const netPubFromSecpPub = function (
  secpPubkey: Uint8Array,
  network: "MainNet" | "TestNet" = "MainNet",
) {
  const pubHash = crypto.createHash("sha256").update(secpPubkey).digest();
  const pubHashRMD160 = crypto.createHash("ripemd160").update(pubHash).digest();
  const pubHashNetwork = [util.PUBKEY_ADDRESS[network]].concat(
    pubHashRMD160.toJSON().data,
  );
  const pubHash2 = crypto
    .createHash("sha256")
    .update(Buffer.from(pubHashNetwork))
    .digest();
  const pubHash3 = crypto.createHash("sha256").update(pubHash2).digest();
  const chcksumPub = util
    .byteToHexString(pubHash3.subarray(0, 4))
    .toUpperCase();
  const pubPreBase = `${util.byteToHexString(
    Uint8Array.from(pubHashNetwork),
  )}${chcksumPub}`;
  // Return the Network-Encoded pubkey (SCC address)
  return util.to_b58(util.hexStringToByte(pubPreBase));
};

/**
 * (network) Pubkey Derivation from (network) private key (WIF)
 *
 * @param privkey
 * @param rawBytes
 * @param pubBytesOnly
 * @returns
 */
export const pubFromPriv = function (
  privkey: Uint8Array | string,
  rawBytes = false,
  pubBytesOnly = false,
  network: "MainNet" | "TestNet" = "MainNet",
) {
  const bArrConvert = rawBytes ? privkey : util.from_b58(privkey);
  const droplfour = bArrConvert.slice(0, bArrConvert.length - 4);
  const key = droplfour.slice(1, droplfour.length);
  const privkeyBytes = key.slice(0, key.length - 1);
  const pubkeyExt = secp256k1.getPublicKey(privkeyBytes, true);
  if (pubBytesOnly) return pubkeyExt;
  return netPubFromSecpPub(pubkeyExt, network);
};

/**
 * Wallet Generation
 *
 * @returns
 */
export const generateWallet = async function (
  network: "MainNet" | "TestNet" = "MainNet",
) {
  // Private Key Generation
  const randBytes = crypto.randomBytes(32);
  const privHex = util.byteToHexString(randBytes).toUpperCase();
  const privWithVersion =
    util.SECRET_KEY[network].toString(16) + privHex + "01";
  const privHash1 = crypto
    .createHash("sha256")
    .update(util.hexStringToByte(privWithVersion))
    .digest();
  const privHash2 = crypto
    .createHash("sha256")
    .update(privHash1)
    .digest("hex")
    .toUpperCase();
  const chcksum = String(privHash2).substring(0, 8).toUpperCase();
  const keyWithChcksum = privWithVersion + chcksum;
  const privkeyBytes = util.hexStringToByte(keyWithChcksum);
  const privkeyWIF = util.to_b58(privkeyBytes);

  // Derive the public key
  const pubKey = pubFromPriv(privkeyBytes, true, false, network);

  // Return wallet object
  return {
    pubkey: pubKey,
    privkey: privkeyWIF,
  };
};
export { tx };
