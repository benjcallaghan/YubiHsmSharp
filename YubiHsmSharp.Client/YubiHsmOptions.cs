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
