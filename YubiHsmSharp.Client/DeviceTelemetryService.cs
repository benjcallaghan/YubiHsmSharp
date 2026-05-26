using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace YubiHsmSharp.Client;

internal class DeviceTelemetryService(IServiceScopeFactory scopeFactory, string? serviceKey) : BackgroundService
{
    internal const string MeterName = "YubiHsmSharp.Client";
    private static readonly Meter Meter = new(MeterName);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan recurrence = TimeSpan.FromMinutes(5);
        PeriodicTimer timer = new(recurrence);

        do
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var connector = serviceKey is null
                ? scope.ServiceProvider.GetRequiredService<YubiConnector>()
                : scope.ServiceProvider.GetRequiredKeyedService<YubiConnector>(serviceKey);

            var device = connector.GetDeviceInfo();
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}