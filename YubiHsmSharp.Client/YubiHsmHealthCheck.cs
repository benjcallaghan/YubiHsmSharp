using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace YubiHsmSharp.Client;

internal class YubiHsmHealthCheck(IServiceProvider serviceProvider, string? serviceKey) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {            
            await using var scope = serviceProvider.CreateAsyncScope();
            var session = serviceKey is null
                ? scope.ServiceProvider.GetRequiredService<YubiSession>()
                : scope.ServiceProvider.GetRequiredKeyedService<YubiSession>(serviceKey);
            session.BlinkDevice(TimeSpan.FromSeconds(1)); // Least intrusive method
            return HealthCheckResult.Healthy();
        }
        catch (Exception e)
        {
            return HealthCheckResult.Unhealthy(exception: e);
        }
    }
}