namespace YubiHsmSharp;

/// <summary>
/// Whether a device option is enabled in a device-global setting.
/// </summary>
public enum DeviceOption
{
    /// <summary>
    /// Option disabled
    /// </summary>
    Disabled = 0,

    /// <summary>
    /// Option enabled
    /// </summary>
    Enabled = 1,

    /// <summary>
    /// Option permanently enabled (only possible to turn off through factory reset)
    /// </summary>
    Permanent = 2,
}