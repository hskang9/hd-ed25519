import {mnemonicGenerate, mnemonicToSeed} from "@polkadot/util-crypto/mnemonic";
import {SpeckleHDKey} from "./index";

describe('test hdkey lib', () => {
    it('hdkey', () => {
        var mnemonic = mnemonicGenerate();
        var seed = mnemonicToSeed(mnemonic);
        var hdkey = new SpeckleHDKey(seed);
        console.log(hdkey.getKeyPair());
    });

    it('derive', () => {
        var mnemonic = mnemonicGenerate();
        var seed = mnemonicToSeed(mnemonic);
        var hdkey = new SpeckleHDKey(seed);
        var derivedKey = hdkey.derive("m/0'/12'/1'/0'");
        console.log(derivedKey);
    })

    it('deriveChild', () => {
        var mnemonic = mnemonicGenerate();
        var seed = mnemonicToSeed(mnemonic);
        var hdkey = new SpeckleHDKey(seed);
        var childKey = hdkey.deriveChild(1);
        console.log(childKey);
    })

    it('deterministic test', () => {
        var mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe"
        var seed = mnemonicToSeed(mnemonic);
        var parentKey = new SpeckleHDKey(seed);
        var childKey = parentKey.derive("m/0'/1'/44'");
        var childKey2 = parentKey.deriveChild(0).deriveChild(1).deriveChild(44);
        expect(childKey2.getKeyPair() ==  childKey.getKeyPair());
    })
})
