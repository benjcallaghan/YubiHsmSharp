# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

### `IAsymmetricBlockCipher`
* `YubiRsaPkcsBlockCipher` - Signs and decrypts data using on-device RSA-PKCS#1v1.5.
* `YubiRsaPssBlockCipher` - Signs data using on-device RSA-PSS.

### `IBlockCipher`
* `YubiAesBlockCipher` - Encrypts and decrypts data using on-device AES.

### `ICipherParameters`
* `YubiECPrivateKeyParameters` - Contains the Object ID of an asymmetric key. Usable only with `YubiEcdsa`.
* `YubiECPublicKeyParameters` - Contains the Object ID and public portion of an asymmetric key. Usable with all BouncyCastle ciphers.
* `YubiRsaKeyParameters` - Contains the Object ID and may contain the public portion of an asymmetric key. Private keys are only usable with `YubiRsaPkcsBlockCipher` and `YubiRsaPssBlockCipher`. Public keys are usable with all BouncyCastle ciphers.
* `YubiSymmetricKeyParameter` - Contains the Object ID of a symmetric key. Usable only with `YubiAesBlockCipher`.

### `IRandomGenerator`
* `YubiRandomGenerator` - Generates pseudo-random bytes directly on the device.
