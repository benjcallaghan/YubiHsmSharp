using System.Runtime.InteropServices;
using YubiHsmSharp;

NativeLibrary.SetDllImportResolver(typeof(YubiModule).Assembly, (libraryName, assembly, searchPath) =>
{
    if (libraryName == "yubihsm")
    {
        return NativeLibrary.Load(@"C:\Program Files\Yubico\YubiHSM Shell\bin\libyubihsm.dll");
    }

    return IntPtr.Zero;
});

var builder = WebApplication.CreateBuilder(args);

builder.AddYubiHsmClient("yubihsm");

var app = builder.Build();

app.MapHealthChecks("/healthz");

app.MapPost("/blink", async (YubiSession session, int seconds) =>
{
    session.BlinkDevice(TimeSpan.FromSeconds(seconds));
    return Results.NoContent();
});

app.Run();
