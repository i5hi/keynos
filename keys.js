const secp256k1 = require('@noble/secp256k1');
const bip32 = require("bip32");
const bip39 = require("bip39");
const crypto = require("crypto");

// use crypto.randomBytes(512) or better as init_entropy
function generateAccessKey(init_entropy){
  const full = crypto.createHash('sha256')
    .update(init_entropy)
    .digest('hex');
  return Buffer.from(full, 'hex').toString('hex').substring(0 ,32);
}

function addSpaces(key){
  return key.replaceAll(/(.{4})/g, '$1 ').trim(); 
}

function removeSpaces(key){
  return key.replaceAll(" ", "");
}

function formatKeyAndPassphrase(key, passphrase){
    const sauce = passphrase?`-${passphrase}`:``;
    return addSpaces(key).toUpperCase()+sauce;
}

async function generateSeed(key, passphrase){
  const sauce = (passphrase)?`-${passphrase}`:``;
  const final_entropy_in = removeSpaces(key).toLowerCase()+sauce;
  console.log({final_entropy_in})
  
  const mnemonic = await bip39.entropyToMnemonic(
    crypto.createHash('sha256').update(final_entropy_in).digest('hex')
  );
  const seed = await bip39.mnemonicToSeed(mnemonic);
  return seed;
}
async function generateRootXPrv(seed){
    return await bip32.fromSeed(seed).toBase58();
}
function deriveHardended3x(parent, derivation_scheme){
  try {
    if (!derivation_scheme.endsWith("/"))
    derivation_scheme+="/";

    derivation_scheme = derivation_scheme.replace("'",  "h").replace("'",  "h").replace("'",  "h");
    derivation_scheme = derivation_scheme.replace("m/",  "");
    if ( derivation_scheme.split("h/").length < 3 ) return new Error({
      code: 400,
      message: "Derivation scheme must contain 3 sub paths."
    });
    const use_case = parseInt(derivation_scheme.split("h/")[0]);
    const index = parseInt(derivation_scheme.split("h/")[1]);
    const revoke = parseInt(derivation_scheme.split("h/")[2]);
    
    const child_key = bip32.fromBase58(parent)
      .deriveHardened(use_case)
      .deriveHardened(index)
      .deriveHardened(revoke);
    const extended_keys = {
      xpub: child_key.neutered().toBase58(),
      xprv: child_key.toBase58(),
    };
    return extended_keys;
  } catch (error) {
    
    return new Error(error);
  }
}
function extractECDHKeys(extended_keys) {
  try {
    const parent_key = bip32.fromBase58(extended_keys.xprv);
    const pubkey = secp256k1.schnorr.getPublicKey(parent_key.privateKey.toString("hex"));
    const ecdsa_keys = {
      privkey: parent_key.privateKey.toString("hex"),
      pubkey: Buffer.from(pubkey).toString('hex')
    };
    return ecdsa_keys;
  } catch (error) {
    return new Error(error);
  }
}
function computeSharedSecret(ecdh_keys) {
  try{
    ecdh_keys.pubkey = (ecdh_keys.pubkey.length===64)
      ? "02" + ecdh_keys.pubkey
      : ecdh_keys.pubkey;
    const type = "secp256k1";
    let curve = crypto.createECDH(type);
    curve.setPrivateKey(ecdh_keys.privkey, "hex"); 
    return curve.computeSecret(ecdh_keys.pubkey, "hex").toString("hex");
  }
  catch(e){
    return new Error(e);
  }
}
async function schnorrSign(message, privkey) {
  try {
    const signature = await secp256k1.schnorr.sign(
      crypto.createHash('sha256').update(message).digest('hex'), 
      privkey
    );
    return Buffer.from(signature).toString('hex');
  }
  catch (e) {
    return new Error(e);
  }
}
async function schnorrVerify(message,signature, pubkey){
  try {
    return await secp256k1.schnorr.verify(
        signature, 
        crypto.createHash('sha256').update(message).digest('hex'), 
        pubkey
    );
  }
  catch (e) {
    return new Error(e);
  }
}

module.exports = {
    generateAccessKey,
    addSpaces,
    removeSpaces,
    formatKeyAndPassphrase,
    generateSeed,
    generateRootXPrv,
    deriveHardended3x,
    extractECDHKeys,
    computeSharedSecret,
    schnorrSign,
    schnorrVerify
}