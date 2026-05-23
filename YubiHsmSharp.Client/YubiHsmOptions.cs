using System.ComponentModel.DataAnnotations;

namespace YubiHsmSharp.Client;

public class YubiHsmOptions
{
    internal const string DefaultConfigSectionName = "YubiHsm:Client";

    [Required]
    public string Url { get; set; }

    public bool DisableHealthChecks { get; set; }

    [Required]
    public ushort AuthKeyId { get; set; }

    [Required]
    public string Password { get; set; }
}
