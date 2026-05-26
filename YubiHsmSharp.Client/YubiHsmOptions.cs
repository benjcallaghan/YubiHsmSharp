using System.ComponentModel.DataAnnotations;

namespace YubiHsmSharp.Client;

/// <summary>
/// Options for configuring a <see cref="YubiSession"/>.
/// </summary>
public class YubiHsmOptions
{
    internal const string DefaultConfigSectionName = "YubiHsm";

    /// <summary>
    /// Gets or sets the URL used to connect to a YubiHSM 2.
    /// </summary>
    [Required]
    public string Url { get; set; } = null!;

    /// <summary>
    /// Gets or sets whether health checks for this YubiHSM 2 should be disabled.
    /// </summary>
    public bool DisableHealthChecks { get; set; }

    /// <summary>
    /// Gets or sets whether device metrics pulled from the YubiHSM 2 should be disabled.
    /// </summary>
    public bool DisableMetrics { get; set; }

    /// <summary>
    /// Gets or sets whether device logs pulled from the YubiHSM 2 should be disabled.
    /// </summary>
    public bool DisableDeviceLogs { get; set; }

    /// <summary>
    /// Gets or sets the interval at which the YubiHSM 2 should be polled for metrics and logs.
    /// </summary>
    /// <remarks>
    /// This value is ignored if both <see cref="DisableMetrics"/> and <see cref="DisableDeviceLogs"/> are true.
    /// </remarks>
    public TimeSpan TelemetryPollInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the ID of the Authentication Key used to connect.
    /// </summary>
    [Required]
    public ushort AuthKeyId { get; set; }

    /// <summary>
    /// Gets or sets the password associated with the Authentication Key.
    /// </summary>
    [Required]
    public string Password { get; set; } = null!;
}
