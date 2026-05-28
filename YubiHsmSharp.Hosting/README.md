# YubiHsmSharp.Hosting

A .NET Aspire Hosting Integration that defines a YubiHSM 2 resource.

## Example

The following code accepts an Authentication Key ID and a Password as parameters, and then uses them to configure a YubiHSM 2 resource. The resource is then consumed by a demo project.

```csharp
var builder = DistributedApplication.CreateBuilder(args);

var authKeyId = builder.AddParameter("YubiHsm-AuthKeyId");
var password = builder.AddParameter("YubiHsm-Password", secret: true);

var yubihsm = builder.AddYubiHsm("yubihsm", "http://localhost:12345")
    .WithPassword(authKeyId, password);

builder.AddProject<Projects.YubiHsmSharp_Demo>("demo")
    .WithReference(yubihsm);

builder.Build().Run();
```

## Demo

See [`YubiHsmSharp.AppHost`](../YubiHsmSharp.AppHost/) for a demo of this library.