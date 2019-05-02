# speckle-hdkey-lib

Hierarchical Deterministic Keys for Parachains and Substrate-based chains in the Polkadot network
[proposal](./proposal.mediawiki)

# Installation
`npm i --save speckle-hdkey-lib`

# Usage
```typescript
import {mnemonicGenerate, mnemonicToSeed} from '@polkadot/util-crypto'
import HDKey from 'speckle-hdkey-lib'
import Keyring from '@polkadot/keyring';

var mnemonic = mnemonicGenerate() // # of words: 12(default), 15, 18, 21, 24
var seed = mnemonicToSeed(mnemonic)
var hdkey = HDKey(seed)
var keyring = new Keyring()
keyring.addPair(hdkey.getKeyPair())
keyring.getPairs()
```

# Hierarchy Derivation

Derived keys save Extended keys and index to generate Child keys

# Usage
```typescript
var derivdedKey = hdkey.derive("m/0'/12'/1'/0'")

// Generate multiple accounts in the same depth
var childKey1 = derivedKey.deriveChild(1); // derive("m/0'/12'/1'/0'/1'")
var childKey2 = derivedKey.deriveChild(2); // derive("m/0'/12'/1'/0'/2'")
var childKey3 = derivedKey.deriveChild(3); // derive("m/0'/12'/1'/0'/3'")
```

# Registered Chain Type

TODO: Make Registered chain type table


