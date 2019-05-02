const config = require('@polkadot/dev/config/jest');

module.exports = Object.assign({}, config, {
    moduleNameMapper: {
        '@polkadot/keyring(.*)$': '<rootDir>/node_modules/@polkadot/keyring/$1',
        '@polkadot/util-(crypto|rlp)(.*)$': '<rootDir>/node_modules/@polkadot/util-$1/$2',
        '@polkadot/util(.*)$': '<rootDir>/node_modules/@polkadot/util/$1'
    },
    modulePathIgnorePatterns: [
        '<rootDir>/node_modules/@polkadot/keyring/build',
        '<rootDir>/node_modules/@polkadot/util/build',
        '<rootDir>/node_modules/@polkadot/util-crypto/build'
    ]
});
