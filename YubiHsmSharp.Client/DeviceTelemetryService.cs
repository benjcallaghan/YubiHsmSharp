using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace YubiHsmSharp.Client;

internal class DeviceTelemetryService(IServiceScopeFactory scopeFactory, string? serviceKey) : BackgroundService
{
    internal const string MeterName = "YubiHsmSharp.Client";
    private static readonly Meter Meter = new(MeterName);

    private static readonly Gauge<byte> LogTotal = Meter.CreateGauge<byte>(
        name: "yubihsm.log.available",
        unit: "{logs}",
        description: "The current number of available logs stored in the device"
    );
    private static readonly Gauge<byte> LogUsed = Meter.CreateGauge<byte>(
        name: "yubihsm.log.used",
        unit: "{logs}",
        description: "The current number of used logs stored in the device"
    );

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan recurrence = TimeSpan.FromMinutes(5);
        PeriodicTimer timer = new(recurrence);

        do
        {
            try
            {
                await PollDevice();
            }
            catch
            {
                // We shouldn't crash the service if a single polling cycle fails.
                // FIXME: What should we do with the error?
                // It should still be reported somehow.
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task PollDevice()
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var connector = serviceKey is null
            ? scope.ServiceProvider.GetRequiredService<YubiConnector>()
            : scope.ServiceProvider.GetRequiredKeyedService<YubiConnector>(serviceKey);

        var device = connector.GetDeviceInfo();
        TagList deviceTags = [
            new("yubihsm.version", $"{device.Major}.{device.Minor}.{device.Patch}"),
                new("yubihsm.serial", device.Serial),
            ];

        LogTotal.Record(device.LogTotal, in deviceTags);
        LogUsed.Record(device.LogUsed, in deviceTags);
    }
}