import {
  mnemonicGenerate,
  mnemonicToSeed, mnemonicValidate,
  naclKeypairFromSeed, naclSign, naclVerify,
} from "@polkadot/util-crypto"
const assert = require("assert");
import wasmCrypto from "@polkadot/wasm-crypto";
import {createHmac} from "crypto";
import deriveHard from "@polkadot/util-crypto/nacl/deriveHard";
const MASTER_SECRET = "sr25519 seed";

describe("Account Generation", () => {
  test("sr25519", async () => {
    // init wasm
    await wasmCrypto.waitReady();

    // Generate keypair
    var bip39 = wasmCrypto.bip39Generate(12)
    var seed = wasmCrypto.bip39ToSeed(bip39, "password");
    var sr25519Keypair = wasmCrypto.sr25519KeypairFromSeed(seed);

    // private key
    var privateKey = sr25519Keypair.slice(0, 64);
    // public key
    var publicKey = sr25519Keypair.slice(64);

    // sign
    var buffer = new ArrayBuffer(32);
    var message = new Uint8Array(buffer, 0, 32);
    var cert = wasmCrypto.sr25519Sign(publicKey, privateKey, message);

    // verify
    var verify = wasmCrypto.sr25519Verify(cert, message, publicKey);
    expect(verify).toEqual(true);
  });
});

describe("Derivation test", () => {
  test("sr25519", async () => {
    // init wasm
    await wasmCrypto.waitReady();

    // Generate keypair
    var mnemonic = wasmCrypto.bip39Generate([12]);
    var seed = wasmCrypto.bip39ToSeed(mnemonic, "password");
    var sr25519Keypair = wasmCrypto.sr25519KeypairFromSeed(seed);

    // Make Chaincode
    var buffer = new ArrayBuffer(32);
    /// chaincode is a secret with high entropy which is provided from privatekey and public key
    // chaincode = createHmac(sha512(keyPair))
    // using [0u8; 32] for example
    var chainCode = new Uint8Array(buffer, 0, 32);

    // derive key
    var derivedKey = wasmCrypto.sr25519DeriveKeypairHard(
      sr25519Keypair,
      chainCode
    );
    // private key
    var privateKey = derivedKey.slice(0, 64);
    // public key
    var publicKey = derivedKey.slice(64);

    // sign
    let message = new Uint8Array(buffer, 0, 32);
    let cert = wasmCrypto.sr25519Sign(publicKey, privateKey, message);

    // verify
    let verify = wasmCrypto.sr25519Verify(cert, message, publicKey);
    expect(verify).toEqual(true);
  });
});

describe("Hierarchy derivation", () => {
  test("derive child", async () => {
    await wasmCrypto.waitReady();

    // Generate parentKey
    let bip39 = wasmCrypto.bip39Generate(12);
    let seed = wasmCrypto.bip39ToSeed(bip39, "password");
    let sr25519Keypair = wasmCrypto.sr25519KeypairFromSeed(seed);

    // parent private key
    let privateKey = sr25519Keypair.slice(0, 64);
    // parent public key
    let publicKey = sr25519Keypair.slice(64);

    let path = "44/60/0/0";
    expect(
      path[0] === "m" || path[0] === "M" || path[0] === "m'" || path[0] === "M'"
    );
    let entries = path.split("/");

    let one_entry = entries[0];
    let indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(one_entry, 0);
    var pk = privateKey;
    var zb = Buffer(1, 0);
    pk = Buffer.concat([zb, pk]);

    let data = Buffer.concat([pk, indexBuffer]);

    var I = wasmCrypto.pbkdf2(data, MASTER_SECRET, 2048);
    var IR = I.slice(32);

    // Parent keypair -> Child keypair
    let childKeyPair = wasmCrypto.sr25519DeriveKeypairHard(sr25519Keypair, IR);

    let childSecKey = childKeyPair.slice(0, 64);
    let childPubKey = childKeyPair.slice(64);
    // chainCode is used for generating next child key with index
    var chainCode = IR;
  });
});


describe('HD in synchrounous manner', async () => {
    test('account generation', () => {
      var mnemonic = mnemonicGenerate(12);
      var seed = mnemonicToSeed(mnemonic);
      var sr25519KeyPair = naclKeypairFromSeed(seed);
      console.log(sr25519KeyPair);
    });

    test('sign & verify', () => {
      var mnemonic = mnemonicGenerate(12);
      var seed = mnemonicToSeed(mnemonic);
      var sr25519KeyPair = naclKeypairFromSeed(seed);

      // sign
      var buffer = new ArrayBuffer(32);
      let message = new Uint8Array(buffer, 0, 32);
      let cert = naclSign(message, sr25519KeyPair);

      // verify
      let verify = naclVerify(message, cert, sr25519KeyPair.publicKey);
      expect(verify).toEqual(true);
    })

    test('hd key derivation', () => {


      // Generate parentKey
      var mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
      assert(mnemonicValidate(mnemonic) == true);
      var seed = mnemonicToSeed(mnemonic);
      var sr25519KeyPair = naclKeypairFromSeed(seed);

      // parent private key
      let privateKey = sr25519KeyPair.secretKey;
      console.log(privateKey.length);
      // parent public key
      let publicKey = sr25519KeyPair.publicKey;
      console.log(publicKey.length);

      let path = "44/60/0/0";
      expect(
          path[0] === "m" || path[0] === "M" || path[0] === "m'" || path[0] === "M'"
      );
      let entries = path.split("/");

      let one_entry = entries[0];
      let indexBuffer = Buffer.allocUnsafe(4);
      indexBuffer.writeUInt32BE(parseInt(one_entry,10), 0);
      var pk = privateKey;
      var zb = Buffer(1, 0);
      pk = Buffer.concat([zb, pk]);

      let data = Buffer.concat([pk, indexBuffer]);
      var I = createHmac('sha512', MASTER_SECRET).update(data).digest();
      var IL = I.slice(0,32);
      var IR = I.slice(32);
      var chainCode = IR;

      var childKeySeed = deriveHard(IL, IR);
      // chainCode is used for generating next child key with index
      var childKeyPair = naclKeypairFromSeed(childKeySeed);

      console.log(childKeyPair);
    })
})

