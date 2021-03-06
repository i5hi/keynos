const keys = require('./keys.js');
const assert = require('assert');
const crypto = require('crypto');

describe('Key Derivation Flow', function () {

    let access_key;
    const passphrase = "supersecretnonsauce";
    let root;
    let ecdh_keys;
    const message = "keynos might actually work." + `:${Date.now()}`;
  it('Generate a 16-byte hex access key', function () {
    access_key = keys.generateAccessKey(crypto.randomBytes(512));
    assert(Buffer.byteLength(access_key, 'hex')===16);
  });

  it("Displays the access key for readability",function(){
    console.log(keys.addSpaces(access_key));
    console.log(keys.formatKeyAndPassphrase(access_key, passphrase));
  })
  it('Generate root Xprv from from access key.', async function () {
    const seed = await keys.generateSeed(access_key,passphrase);
    root = await keys.generateRootXPrv(seed);
    assert(root.startsWith('xprv'));
  });
  it('Derives ECDH keys from seed at path "m/128h/0h/0h"', async function(){
    const derivation_scheme ="m/128h/0h/0h";
    const xkeys = keys.deriveHardended3x(root,derivation_scheme);
    ecdh_keys = keys.extractECDHKeys(xkeys);
    console.log({ecdh_keys});
    assert(Buffer.byteLength(ecdh_keys.privkey, 'utf8'),64);
  });
  it('Signs and verifies a message with new keys', async function(){
    const signature = keys.schnorrSign(message, ecdh_keys.privkey);
    const verification  = keys.schnorrVerify(message, signature,ecdh_keys.pubkey);
    assert(verification);
  })

});