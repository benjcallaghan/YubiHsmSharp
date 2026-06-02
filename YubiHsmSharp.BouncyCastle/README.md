# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

* `YubiAesBlockCipher` implements `IBlockCipher`
* `YubiAsymmetricKeyParameter` implements `KeyParameter`
* `YubiRandomGenerator` implements `IRandomGenerator`
* `YubiRsaKeyParameters` implements `RsaKeyParameters`
* `YubiRsaPkcsBlockCipher` implements `IAsyncBlockCipher`
* `YubiSymmetricKeyParameter` implements `KeyParameter`
