# YubiHsmSharp.Client

A .NET Aspire Client Integration that automatically configures a YubiHSM 2 client.

## Registrations

The extension method `AddYubiHsmClient` registers the following types:
* `YubiModule` - Singleton
* `YubiConnector` - Scoped, pre-configured with URL
* `YubiSession` - Scoped, pre-configured with Authentication Key ID and Password

The method also registers the following internal types, used to enhance observability, but not exposed to the application:
* A health check that verifies connectivity and authentication for the corresponding `YubiSession`, unless `DisableHealthChecks=true`.
* A background service that pulls metrics and logs from the corresponding `YubiSession`, unless both `DisableMetrics=true` and `DisableDeviceLogs=true`.

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