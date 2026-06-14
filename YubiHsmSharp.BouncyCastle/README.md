# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-defined interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

### `IAsymmetricBlockCipher`
* `YubiRsaOaep` - Decrypts data using on-device RSA-OAEP.
* `YubiRsaPkcs` - Signs and decrypts data using on-device RSA-PKCS#1v1.5.
* `YubiRsaPss` - Signs data using on-device RSA-PSS.

### `IAsymmetricCipherKeyPairGenerator`
* `YubiEcdsaKeyGenerator` - Generates and stores an EC key pair directly on the device.
* `YubiEddsaKeyGenerator` - Generates and stores an ED key pair directly on the device.
* `YubiRsaKeyGenerator` - Generates and stores an RSA key pair directly on the device.

### `IBasicAgreement`
* `YubiEcdh` - Generates a shared ECDH secret using a stored private key.

### `IBlockCipher`
* `YubiAes` - Encrypts and decrypts data using on-device AES.

### `IBufferedCipher`
* `YubiAesCbc` - Encrypts and decrypts data using on-device AES/CBC.

### `CipherKeyGenerator`
* `YubiAesKeyGenerator` - Generates and stores a new AES key directly on the device.
* `YubiHmacKeyGenerator` - Generates and stores a new HMAC key directly on the device.
* `YubiWrapKeyGenerator` - Generates and stores a new Wrap key directly only the device.

### `ICipherParameters`
* `YubiECPrivateKeyParameters` - Contains the Object ID of an asymmetric key. Usable only with `YubiEcdsa`.
* `YubiECPublicKeyParameters` - Contains the Object ID and public portion of an asymmetric key. Usable with all BouncyCastle ciphers.
* `YubiEd25519PrivateKeyParameters` - Contains the Object ID of an asymmetric key. Usable only with `YubiEddsa`.
* `YubiEd25519PublicKeyParameters` - Contains the Object ID and public portion of an asymmetric key. Usable with all BouncyCastle ciphers.
* `YubiHmacKeyParameter` - Contains the Object ID of an HMAC key. Usable only with `YubiHmac`.
* `YubiRsaKeyParameters` - Contains the Object ID and may contain the public portion of an asymmetric key. Private keys are only usable with `YubiRsaOaep`, `YubiRsaPkcs`, and `YubiRsaPss`. Public keys are usable with all BouncyCastle ciphers.
* `YubiSymmetricKeyParameter` - Contains the Object ID of a symmetric key. Usable only with `YubiAes` and `YubiAesCbc`.
* `YubiWrapKeyParameter` - Contains the Object ID of a wrap key. Usable only with `YubiWrap`.

### `IDsa`
* `YubiEcdsa` - Signs data using on-device ECDSA.

### `KeyGenerationParameters`
* `YubiKeyGenerationParameters` - Contains metadata to be associated with a generated and stored key. Only usable with `Yubi...KeyGenerator` generators.
* `YubiDelegationKeyGenerationParameters` - Contains metadata to be associated with a generated and stored key. Only usable with `YubiWrapKeyGenerator`.

### `IMac`
* `YubiHmac` - Signs data using on-device HMAC.

### `IRandomGenerator`
* `YubiRandomGenerator` - Generates pseudo-random bytes directly on the device.

### `ISigner`
* `YubiEddsa` - Signs data using on-device Ed25519.

### `IWrapper`
* `YubiWrap` - Wraps and unwraps data using on-device Wrap methods.