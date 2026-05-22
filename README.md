# YubiHsmSharp

A collection of libraries for working with YubiHSM 2 in C#/.NET.

## Libraries

* [`YubiHsmSharp`](./YubiHsmSharp/README.md): A C# wrapper around libyubihsm with idomatic .NET types.
* [`YubiHsmSharp.BouncyCastle`](./YubiHsmSharp.BouncyCastle/README.md): A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces.
* [`YubiHsmSharp.PciPin`](./YubiHsmSharp.PciPin/README.md): An implementation of PCI-compatible PIN cryptography methods that store sensitive keys in a YubiHSM 2.