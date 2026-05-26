using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace YubiHsmSharp.Client;

internal partial class DeviceTelemetryService(IServiceScopeFactory scopeFactory, ILogger<DeviceTelemetryService> logger, string? serviceKey)
 : BackgroundService
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
    private static readonly Counter<ushort> UnloggedBoot = Meter.CreateCounter<ushort>(
        name: "yubihsm.unlogged.boot",
        unit: "{logs}",
        description: "The number of unlogged boot entries due to a full buffer"
    );
    private static readonly Counter<ushort> UnloggedAuth = Meter.CreateCounter<ushort>(
        name: "yubihsm.unlogged.auth",
        unit: "{logs}",
        description: "The number of unlogged authentication entries due to a full buffer"
    );

    [LoggerMessage(Level = LogLevel.Information, Message = "Received log entry from device: {LogEntry}.")]
    private partial void LogDeviceEntry(LogEntry logEntry);

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
        var session = serviceKey is null
            ? scope.ServiceProvider.GetRequiredService<YubiSession>()
            : scope.ServiceProvider.GetRequiredKeyedService<YubiSession>(serviceKey);

        var device = connector.GetDeviceInfo();
        TagList deviceTags = [
            new("yubihsm.version", $"{device.Major}.{device.Minor}.{device.Patch}"),
            new("yubihsm.serial", device.Serial),
        ];

        LogTotal.Record(device.LogTotal, in deviceTags);
        LogUsed.Record(device.LogUsed, in deviceTags);

        Span<LogEntry> logs = stackalloc LogEntry[62]; // Maximum number of log entries supported in device
        var (unloggedBoot, unloggedAuth, logsLength) = session.GetLogEntries(logs);
        logs = logs[..logsLength];

        UnloggedBoot.Add(unloggedBoot, in deviceTags);
        UnloggedAuth.Add(unloggedAuth, in deviceTags);

        foreach (var log in logs)
        {
            LogDeviceEntry(log);
        }

        session.SetLogIndex(logs[^1].Number);
    }
}