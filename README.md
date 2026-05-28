# YubiHsmSharp

A collection of libraries for working with YubiHSM 2 in C#/.NET.

## Libraries

* [`YubiHsmSharp`](./YubiHsmSharp/): A C# wrapper around libyubihsm with idomatic .NET types.
* [`YubiHsmSharp.BouncyCastle`](./YubiHsmSharp.BouncyCastle/): A compatibility shim that exposes YubiHSM 2 operations through BouncyCastle-compatible interfaces.
* [`YubiHsmSharp.Client`](./YubiHsmSharp.Client/): A .NET Aspire Client Integration that automatically configures a YubiHSM 2 client.
* [`YubiHsmSharp.Hosting`](./YubiHsmSharp.Hosting/): A .NET Aspire Hosting Integration that defines a YubiHSM 2 resource.
* [`YubiHsmSharp.PciPin`](./YubiHsmSharp.PciPin/): An implementation of PCI-compatible PIN cryptography methods that store sensitive keys in a YubiHSM 2.

## Demos

* [`YubiHsmSharp.AppHost`](./YubiHsmSharp.AppHost/): A demo AppHost project showing how to use YubiHsmSharp in a .NET Aspire workspace.
* [`YubiHsmSharp.Demo`](./YubiHsmSharp.Demo/): A demo Web API project showing how to use YubiHsmSharp in a .NET application.