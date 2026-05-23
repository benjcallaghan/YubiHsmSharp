using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace YubiHsmSharp.Client;

internal class YubiHsmHealthCheck(YubiSession session) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            session.BlinkDevice(TimeSpan.FromSeconds(1)); // Least intrusive method
            return Task.FromResult(HealthCheckResult.Healthy());
        }
        catch (Exception e)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(exception: e));
        }
    }
}