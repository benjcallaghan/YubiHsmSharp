# YubiHsmSharp.Client

An extension to .NET Hosting to configure a YubiHSM client for an application.

## Registrations

The extension method `AddYubiHsmClient` registers the following types:
* `YubiModule` - Singleton
* `YubiConnector` - Scoped, pre-configured with URL
* `YubiSession` - Scoped, pre-configured with Authentication Key ID and Password

The method also registers a health check for the corresponding `YubiSession`, unless the setting `DisableHealthChecks=true`. The default behavior is to register health checks.

## Example

The following code registers a `YubiSession` that is configured with a URL, Authentication Key ID, and Password retrieved from app configuration.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.AddYubiHsmClient("yubihsm");

var app = builder.Build();

app.MapHealthChecks("/healthz");

app.MapPost("/blink", async (YubiSession session, int seconds) => {
    session.BlinkDevice(TimeSpan.FromSeconds(seconds));
    return Results.NoContent();
});

app.Run();
```

## Demo

See [`YubiHsmSharp.Demo`](../YubiHsmSharp.Demo/) for a demo of this library.