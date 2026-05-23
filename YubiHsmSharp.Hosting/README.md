# YubiHsmSharp.Hosting

An extension to .NET Aspire to configure a shared YubiHSM 2 service within a distributed application.

## Example

The following code accepts an Authentication Key ID and a Password as parameters, and then uses them to configure a YubiHSM 2 resource. The resource is then consumed by a demo project.

```csharp
var builder = DistributedApplication.CreateBuilder(args);

var authKeyId = builder.AddParameter("YubiHsm-AuthKeyId");
var password = builder.AddParameter("YubiHsm-Password");

var yubihsm = builder.AddYubiHsm("yubihsm", "http://localhost:12345")
    .WithPassword(authKeyId, password);

builder.AddProject<Projects.YubiHsmSharp_Demo>("demo")
    .WithReference(yubihsm);

builder.Build().Run();
```

## Demo

See [`YubiHsmSharp.AppHost`](../YubiHsmSharp.AppHost/) for a demo of this library.