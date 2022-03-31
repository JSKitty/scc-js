const secp256k1 = require('@noble/secp256k1')
const Crypto = require('crypto');
const varuint = require('./varuint')
const wallet = require('./wallet');
const util = require('./util');


function sha256 (b) {
  return Crypto.createHash('sha256')
    .update(b)
    .digest()
}
function hash256 (buffer) {
  return sha256(sha256(buffer))
}

function encodeSignature (signature, recovery, compressed) {
    if (compressed) recovery += 4
    return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
}

function decodeSignature (buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length')

  const flagByte = buffer.readUInt8(0) - 27
  if (flagByte > 15 || flagByte < 0) {
    throw new Error('Invalid signature parameter')
  }

  return {
    compressed: !!(flagByte & 12),
    recovery: flagByte & 3,
    signature: buffer.slice(1)
  }
}

function magicHash (message, messagePrefix) {
  messagePrefix = messagePrefix || '\x19DarkCoin Signed Message:\n'
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8')
  }
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, 'utf8')
  }
  const messageVISize = varuint.encodingLength(message.length)
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length
  )
  messagePrefix.copy(buffer, 0)
  varuint.encode(message.length, buffer, messagePrefix.length)
  message.copy(buffer, messagePrefix.length + messageVISize)
  return hash256(buffer)
}

function prepareSign (
  messagePrefixArg,
  sigOptions
) {
  if (typeof messagePrefixArg === 'object' && sigOptions === undefined) {
    sigOptions = messagePrefixArg
    messagePrefixArg = undefined
  }
  let {extraEntropy } = sigOptions || {extraEntropy: true}
  return {
    messagePrefixArg,
    extraEntropy
  }
}

function sign (
  message,
  privateKey,
  compressed,
  messagePrefix,
  sigOptions
) {
  const {
    messagePrefixArg,
    extraEntropy
  } = prepareSign(messagePrefix, sigOptions)
  const hash = magicHash(message, messagePrefixArg)

  const privateKeyBytes = util.wifToBytes(privateKey)
  // Default 'compressed' to true
  if (compressed === undefined) compressed = true;

  // extraEntropy will also default to 'true' if left unset
  return secp256k1.sign(hash, privateKeyBytes, {recovered:true, der:false, extraEntropy:extraEntropy}).then(function(result){
    return encodeSignature(
        result[0],
        result[1],
        compressed
      )
  });
}

function verify (message, address, signature, messagePrefix) {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64')

  const parsed = decodeSignature(signature)

  const hash = magicHash(message, messagePrefix)
  const publicKey = secp256k1.recoverPublicKey(
    hash,
    parsed.signature,
    parsed.recovery,
    parsed.compressed
  );

  return address === wallet.netPubFromSecpPub(publicKey);
}

module.exports = {
  magicHash: magicHash,
  sign: sign,
  verify: verify
}