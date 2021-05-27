const { Ed25519KeyPair } = require('crypto-ld');
const jsonld = require('jsonld');
// const util = require('./rdf-sig.js');
const util = require('jsonld-signatures/lib/util.js');
const graphy = require('graphy');

module.exports = {
  Ed25519KeyPair,
  jsonld,
  util,
  graphy,
  Buffer: require('buffer').Buffer,
}
