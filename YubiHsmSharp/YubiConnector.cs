using System.Runtime.Versioning;

namespace YubiHsmSharp;

/// <summary>
/// Represents a (pending) connection to a YubiHSM device.
/// </summary>
public sealed class YubiConnector : IDisposable
{
    private static readonly SafeConnectorHandle NullConnectorHandle = new();

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
            yh_rc err = yh_get_verbosity(out Verbosity value);
            YubiHsmException.ThrowIfError(err);
            return value;
        }
        set
        {
            yh_rc err = yh_set_verbosity(NullConnectorHandle, value);
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
        yh_rc err = yh_set_verbosity(this.handle, verbosity);
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

    /// <summary>
    /// Connect to the device through this connector.
    /// </summary>
    /// <param name="timeout">Connection timeout in seconds, 0 for no timeout.</param>
    public void Connect(int timeout = 0)
    {
        yh_rc err = yh_connect(this.handle, timeout);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Sends a plaintext message to the device through this connector.
    /// </summary>
    /// <param name="request">The command to send.</param>
    /// <param name="requestData">The request data to send.</param>
    /// <param name="responseBuffer">The buffer to receive the response.</param>
    /// <param name="responseLength">The length of the received response.</param>
    /// <returns>The response command.</returns>
    /// <seealso cref="YubiSession.SendMessage"/> 
    public Command SendMessage(Command request, ReadOnlySpan<byte> requestData, Span<byte> responseBuffer, out int responseLength)
    {
        yh_rc err = yh_send_plain_msg(this.handle, request, requestData, (nuint)requestData.Length,
            out Command responseCmd, responseBuffer, out nuint responseLen);
        YubiHsmException.ThrowIfError(err);
        responseLength = (int)responseLen;
        return responseCmd;
    }

    /// <summary>
    /// Creates a new session using an encryption key and MAC key derived from a password.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="password">The password to derive the keys from</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the password in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> password, bool recreateSession = false)
    {
        yh_rc err = yh_create_session_derived(this.handle, authKeyId, password, (nuint)password.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    /// <summary>
    /// Creates a new session using the provided encryption key and MAC key.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="encryptionKey">The encryption key</param>
    /// <param name="macKey">The MAC key</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the keys in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> macKey, bool recreateSession = false)
    {
        yh_rc err = yh_create_session(this.handle, authKeyId, encryptionKey, (nuint)encryptionKey.Length, macKey, (nuint)macKey.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    /// <summary>
    /// Creates a new session using encryption keys from a platform-specific key store.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="utf8EncryptionKeyName">The name of the encryption key in the key store, UTF-8 encoded and null-terminated</param>
    /// <param name="utf8MacKeyName">The name of the MAC key in the key store, UTF-8 encoded and null-terminated</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> utf8EncryptionKeyName, ReadOnlySpan<byte> utf8MacKeyName)
    {
        yh_rc err = yh_create_session_ex(this.handle, authKeyId, utf8EncryptionKeyName, utf8MacKeyName, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    /// <summary>
    /// Creates a new session using an asymmetric key pair.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Asymmetric Authentication Key used to authenticate the session</param>
    /// <param name="clientPrivateKey">The private key of the client</param>
    /// <param name="devicePublicKey">The public key of the device</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSessionAsymmetric(ushort authKeyId, ReadOnlySpan<byte> clientPrivateKey, ReadOnlySpan<byte> devicePublicKey)
    {
        // FIXME: Is the public key parameter necessary?
        // yh_create_session_asym currently requires both the client private key and device public key,
        // but the device public key could be retrieved from the device using yh_util_get_device_pubkey.
        // Additionally, the yubihsm shell does NOT ask for the public key.
        yh_rc err = yh_create_session_asym(this.handle, authKeyId, clientPrivateKey, (nuint)clientPrivateKey.Length, devicePublicKey, (nuint)devicePublicKey.Length, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    // TODO: yh_begin_create_session and yh_finish_create_session for external authentication

    /// <summary>
    /// Gets the value and algorithm of the device public key.
    /// </summary>
    /// <param name="responseBuffer">Buffer to store the public key value</param>
    /// <param name="responseLength">Output parameter for the length of the public key value</param>
    /// <returns>The algorithm of the device public key</returns>
    public Algorithm GetDevicePublicKey(Span<byte> responseBuffer, out int responseLength)
    {
        yh_rc err = yh_util_get_device_pubkey(this.handle, responseBuffer, out nuint responseLen, out Algorithm alg);
        YubiHsmException.ThrowIfError(err);
        responseLength = (int)responseLen;
        return alg;
    }

    /// <summary>
    /// Disconnect from the device and clean up resources associated with this connector.
    /// </summary>
    public void Dispose()
    {
        this.handle.Dispose();
    }
}

internal class SafeConnectorHandle : SafeHandle
{
    public SafeConnectorHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        yh_rc err = yh_disconnect(this.handle);
        return err == yh_rc.YHR_SUCCESS;
    }
}