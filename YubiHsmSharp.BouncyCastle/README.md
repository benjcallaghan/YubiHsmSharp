# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

* `YubiAesBlockCipher` implements `IBlockCipher`
* `YubiRandomGenerator` implements `IRandomGenerator`
* `YubiRsaKeyParameters` implements `RsaKeyParameters`
* `YubiRsaPkcsBlockCipher` implements `IAsymmetricBlockCipher`
* `YubiRsaPssBlockCipher` implements `IAsymmetricBlockCipher`
* `YubiSymmetricKeyParameter` implements `KeyParameter`

### Key Parameters

The provided implementations of `ICipherParameters` only work with the ciphers and implementations provided by this library. The key parameters contain only the identifier of the key within a YubiHSM 2 device. Thus, there is no key data to use with standard BouncyCastle-implemented ciphers.