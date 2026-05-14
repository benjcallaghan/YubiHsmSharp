using System.Runtime.InteropServices;
using System.Runtime.Versioning;

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

    /// <summary>
    /// Sets the CA certificate file path to validate the connector with. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the CA certificate file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetCertificateAuthority(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_CA, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the proxy server URL to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8ProxyUrl">The proxy server URL, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetProxyServer(ReadOnlySpan<byte> utf8ProxyUrl)
    {
        fixed (byte* pUtf8ProxyUrl = utf8ProxyUrl)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_PROXY_SERVER, pUtf8ProxyUrl);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the client certificate file path to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the client certificate file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetClientCertificate(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_CERT, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the client certificate key file path to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the client certificate key file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetClientCertificateKey(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_KEY, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the no-proxy list for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8NoProxy">The no-proxy list, comma-separated, UTF-8 encoded, and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetNoProxy(ReadOnlySpan<byte> utf8NoProxy)
    {
        fixed (byte* pUtf8NoProxy = utf8NoProxy)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_NOPROXY, pUtf8NoProxy);
            YubiHsmException.ThrowIfError(err);
        }
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