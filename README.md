# YubiHsmSharp

A collection of libraries for working with YubiHSM 2 in C#/.NET.

## Libraries

* [`YubiHsmSharp`](./YubiHsmSharp/): A C# wrapper around libyubihsm with idomatic .NET types.
* [`YubiHsmSharp.BouncyCastle`](./YubiHsmSharp.BouncyCastle/): A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces.
* [`YubiHsmSharp.Client`](./YubiHsmSharp.Client/): An extension to .NET Hosting to configure a YubiHSM client for an application.
* [`YubiHsmSharp.Hosting`](./YubiHsmSharp.Hosting/): An extension to .NET Aspire to configure a shared YubiHSM 2 service.
* [`YubiHsmSharp.PciPin`](./YubiHsmSharp.PciPin/): An implementation of PCI-compatible PIN cryptography methods that store sensitive keys in a YubiHSM 2.

## Demos

* [`YubiHsmSharp.AppHost`](./YubiHsmSharp.AppHost/): A demo AppHost project showing how to use YubiHsmSharp in a .NET Aspire workspace.
* [`YubiHsmSharp.Demo`](./YubiHsmSharp.Demo/): A demo Web API project showing how to use YubiHsmSharp in a .NET application.