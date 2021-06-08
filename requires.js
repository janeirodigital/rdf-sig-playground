const CryptoLd = require('crypto-ld');
const forge = require('node-forge');
const {util: {binary: {base58}}} = forge;

module.exports = {
  Ed25519KeyPair: CryptoLd.Ed25519KeyPair,
  jsonld: require('jsonld'),
  util: require('jsonld-signatures/lib/util.js'),
  graphy: require('graphy'),
  Buffer: require('buffer').Buffer,
  jsYaml: require('js-yaml'),
  base58: base58,
}
