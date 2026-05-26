using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace YubiHsmSharp.Client;

internal partial class DeviceTelemetryService(
    IServiceScopeFactory scopeFactory,
    ILogger<DeviceTelemetryService> logger,
    IOptionsMonitor<YubiHsmOptions> options,
    string? serviceKey
) : BackgroundService
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

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to read telemetry from YubiHSM 2 device.")]
    private partial void LogPollException(Exception ex);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        PeriodicTimer timer = new(options.Get(serviceKey).TelemetryPollInterval);
        do
        {
            try
            {
                PollDevice();
            }
            catch (Exception e)
            {
                LogPollException(e);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private void PollDevice()
    {
        using var scope = scopeFactory.CreateScope();
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

        if (!options.Get(serviceKey).DisableDeviceLogs)
        {
            ReadLogs(scope, in deviceTags);
        }
    }

    private void ReadLogs(IServiceScope scope, in TagList deviceTags)
    {
        var session = serviceKey is null
            ? scope.ServiceProvider.GetRequiredService<YubiSession>()
            : scope.ServiceProvider.GetRequiredKeyedService<YubiSession>(serviceKey);

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