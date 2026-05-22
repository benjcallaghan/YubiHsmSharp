# YubiHsmSharp.BouncyCastle

A compatibility shim that exposes YubiHSM 2 operations as BouncyCastle-compatible interfaces. All cryptography performed by these classes occurs externally in the YubiHSM 2 device.

## Supported Types

* `YubiAesBlockCipher` implements `IBlockCipher`
* `YubiRandomGenerator` implements `IRandomGenerator`
* `YubiSymmetricKeyParameter` implements `KeyParameter`