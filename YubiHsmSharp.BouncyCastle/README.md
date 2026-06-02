# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

### `IAsymmetricBlockCipher`
* `YubiRsaPkcsBlockCipher` - Signs and decrypts data using on-device RSA-PKCS#1v1.5.
* `YubiRsaPssBlockCipher` - Signs data using on-device RSA-PSS.

### `IBlockCipher`
* `YubiAesBlockCipher` - Encrypts and decrypts data using on-device AES.

### `IRandomGenerator`
* `YubiRandomGenerator` - Generates pseudo-random bytes directly on the device.

### Key Parameters

The provided implementations of `ICipherParameters` only work with the ciphers and implementations provided by this library. The key parameters contain only the identifier of the key within a YubiHSM 2 device. Thus, there is no key data to use with standard BouncyCastle-implemented ciphers.