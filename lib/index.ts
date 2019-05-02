import { Keypair } from "@polkadot/util-crypto/types";
import { createHmac } from "crypto";
import { naclKeypairFromSeed } from "@polkadot/util-crypto/nacl";

const assert = require("assert");
const HARDENED_OFFSET = 0x80000000;
const MASTER_SECRET = Buffer.from("ed25519 seed", "utf8");
const pathRegex = new RegExp("^m(\\/[0-9]+')+$");
const replaceDerive = (val: string) => val.replace("'", "");

export type ExtendedKey = {
  key: Buffer;
  chainCode: Buffer;
};

export class HDKey {
  depth: number;
  index: Array<number>;
  extendedKey: ExtendedKey;

  constructor(seed: Uint8Array) {
    this.depth = 0;
    this.index = [];
    const I = createHmac("sha512", MASTER_SECRET)
      .update(seed)
      .digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    this.extendedKey = { key: IL, chainCode: IR };
  }

  getKeyPair(): Keypair {
    return naclKeypairFromSeed(this.extendedKey.key);
  }

  private static isValidPath(path: string) {
    if (!pathRegex.test(path)) {
      return false;
    }

    return !path
      .split("/")
      .slice(1)
      .map(replaceDerive)
      // @ts-ignore
      .some(isNaN);
  }

  derive(path: string): HDKey {
    assert(HDKey.isValidPath(path), "path is invalid");
    let entries = path.split("/").slice(1);
    let hdkey: HDKey = this;

    entries.forEach(c => {
      let hardened = c.length > 1 && c[c.length - 1] === "'";
      assert(hardened == true, "Only hardened index can be derived in ed25519");
      let childIndex = parseInt(c, 10);
      assert(childIndex < HARDENED_OFFSET, "Invalid index");
      hdkey = hdkey.deriveChild(childIndex + HARDENED_OFFSET);
    });
    return hdkey;
  }

  deriveChild(index: number): HDKey {
    index = index >= HARDENED_OFFSET ? index : index + HARDENED_OFFSET;
    let indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);
    let pk = this.extendedKey.key;
    let zb = Buffer.alloc(1, 0);
    let data = Buffer.concat([zb, pk, indexBuffer]);
    const I = createHmac("sha512", this.extendedKey.key)
      .update(data)
      .digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    this.extendedKey = { key: IL, chainCode: IR };
    this.depth += 1;
    this.index.push(index);

    return this;
  }
}
