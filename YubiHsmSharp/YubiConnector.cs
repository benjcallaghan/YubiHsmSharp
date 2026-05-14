using static YubiHsmSharp.yubihsm;

namespace YubiHsmSharp;

/// <summary>
/// Debug levels
/// </summary>
[Flags]
public enum Verbosity
{
    /// <summary>
    /// Debug level quiet. No messages printed out
    /// </summary>
    Quiet = 0x00,

    /// <summary>
    /// Debug level intermediate. Intermediate results printed out
    /// </summary>
    Intermediate = 0x01,

    /// <summary>
    /// Debug level crypto. Crypto results printed out
    /// </summary>
    Crypto = 0x02,

    /// <summary>
    /// Debug level raw. Raw messages printed out
    /// </summary>
    Raw = 0x04,

    /// <summary>
    /// Debug level info. General information messages printed out
    /// </summary>
    Info = 0x08,

    /// <summary>
    /// Debug level error. Error messages printed out
    /// </summary>
    Error = 0x10,

    /// <summary>
    /// Debug level all. All previous options enabled
    /// </summary>
    All = 0xff,
}

/// <summary>
/// Represents a (pending) connection to a YubiHSM device.
/// </summary>
public class YubiConnector
{
    private static readonly SafeConnectorHandle NullConnectorHandle = new SafeConnectorHandle();

    private readonly SafeConnectorHandle handle;

    internal YubiConnector(SafeConnectorHandle handle)
    {
        this.handle = handle;
    }

    /// <summary>
    /// Gets or sets the global verbosity level when executing device commands.
    /// This value may be set before initializing the module.
    /// </summary>
    public static Verbosity Verbosity
    {
        get
        {
            yh_rc err = yh_get_verbosity(out yh_verbosity value);
            YubiHsmException.ThrowIfError(err);
            return (Verbosity)value;
        }
        set
        {
            yh_rc err = yh_set_verbosity(NullConnectorHandle, (yh_verbosity)value);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the verbosity level for this connector instance.
    /// This value overrides the global verbosity for this connector,
    /// but it does not affect other connectors.
    /// </summary>
    /// <param name="verbosity">The verbosity level to set on this connector</param>
    public void SetVerbosity(Verbosity verbosity)
    {
        yh_rc err = yh_set_verbosity(this.handle, (yh_verbosity)verbosity);
        YubiHsmException.ThrowIfError(err);
    }
}

internal class SafeConnectorHandle : SafeHandle
{
    public SafeConnectorHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => throw new NotImplementedException();

    protected override bool ReleaseHandle()
    {
        throw new NotImplementedException();
    }
}