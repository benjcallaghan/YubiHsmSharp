using YubiHsmSharp;

var builder = WebApplication.CreateBuilder(args);

builder.AddYubiHsmClient("yubihsm");

var app = builder.Build();

app.MapHealthChecks("/healthz");

app.MapPost("/blink", async (YubiSession session, int seconds) => {
    session.BlinkDevice(TimeSpan.FromSeconds(seconds));
    return Results.NoContent();
});

app.Run();
