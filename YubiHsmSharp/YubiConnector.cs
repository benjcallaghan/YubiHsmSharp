/*
 * Copyright 2026 Benjamin Callaghan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Runtime.Versioning;
using System.Text;

namespace YubiHsmSharp;

/// <summary>
/// Represents a (pending) connection to a YubiHSM device.
/// </summary>
/// <remarks>
/// The <see cref="YubiModule"/> that creates a connector is expected to outlive the created connector.
/// Disposing the module while the connector is in scope is undefined behavior.
/// </remarks>
public sealed class YubiConnector : IDisposable
{
#if NET9_0_OR_GREATER
    private static readonly Lock globalLock = new();
#else
    private static readonly object globalLock = new();
#endif
    private static readonly SafeConnectorHandle NullConnectorHandle = new();
    private static Arc<DebugFile>? globalDebugFile;

    private readonly YubiModule parent; // Prevents module from being GC'd while connector is in scope.
    private Arc<DebugFile>? debugFile;

    internal YubiConnector(YubiModule parent, SafeConnectorHandle handle)
    {
        this.parent = parent;
        this.Handle = handle;
        this.Handle.SetParent(this.parent.Handle);

        lock (globalLock)
        {
            this.debugFile = globalDebugFile?.Clone();
        }
    }

    internal SafeConnectorHandle Handle { get; }

    /// <summary>
    /// Gets or sets the global verbosity level when executing device commands.
    /// This value may be set before initializing the module.
    /// </summary>
    /// <remarks>
    /// Changing this value has no impact on existing connectors.
    /// The new value will be applied to connectors initialized after this call.
    /// </remarks>
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
    /// Gets whether the connector has a device connected.
    /// </summary>
    public bool HasDevice => yh_connector_has_device(this.Handle);

    /// <summary>
    /// Gets the connector version.
    /// </summary>
    public (byte major, byte minor, byte patch) Version
    {
        get
        {
            yh_rc err = yh_get_connector_version(this.Handle, out byte major, out byte minor, out byte patch);
            YubiHsmException.ThrowIfError(err);
            return (major, minor, patch);
        }
    }

    /// <summary>
    /// Gets the connector address, UTF-8 encoded.
    /// </summary>
    public unsafe ReadOnlySpan<byte> Utf8Address
    {
        get
        {
            yh_rc err = yh_get_connector_address(this.Handle, out nint utf8Address);
            YubiHsmException.ThrowIfError(err);
            return MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)utf8Address);
        }
    }

    /// <summary>
    /// Sets the verbosity level for this connector instance.
    /// </summary>
    /// <remarks>
    /// WARNING: This method also sets the global verbosity level (affecting new connectors, but not existing connectors).
    /// It also sets the connector's debug output to the current global debug output.
    /// </remarks>
    /// <param name="verbosity">The verbosity level to set on this connector</param>
    public void SetVerbosity(Verbosity verbosity)
    {
        yh_rc err = yh_set_verbosity(this.Handle, verbosity);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Redirects the debug output of all future connectors into the specified delegate.
    /// This value may be set before initializing the module.
    /// </summary>
    /// <remarks>
    /// This method has no impact on connectors that are already initialized.
    /// </remarks>
    /// <param name="output">A callback to execute for each line of debug messages.</param>
    public static void SetGlobalDebugOutput(Action<string> output)
    {
        SetDebugOutput(output, NullConnectorHandle);
    }

    private static void SetDebugOutput(Action<string> output, SafeConnectorHandle connectorHandle)
    {
        lock (globalLock)
        {
            globalDebugFile?.IsCurrent = false;
            globalDebugFile?.Dispose();
            globalDebugFile = new Arc<DebugFile>(new());
        }

        _ = Task.Run(async () =>
        {
            DebugFile debug = globalDebugFile.Value;
            yh_set_debug_output(connectorHandle, debug.WriteFile);

            using StreamReader reader = new(debug.ReadStream, Encoding.UTF8);
            while (await reader.ReadLineAsync() is string line)
            {
                output(line);
            }
        });
    }

    /// <summary>
    /// Redirects the connector's debug output into the specified delegate.
    /// </summary>
    /// <remarks>
    /// WARNING: This method also sets the global debug output (affecting new connectors, but not existing connectors).
    /// It also sets the connector's verbosity level to the current global verbosity level.
    /// </remarks>
    /// <param name="output">A callback to execute for each line of debug messages.</param>
    public void SetDebugOutput(Action<string> output)
    {
        SetDebugOutput(output, this.Handle);
        this.debugFile?.Dispose();
        this.debugFile = globalDebugFile?.Clone();
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
            yh_rc err = yh_set_connector_option(this.Handle, yh_connector_option.YH_CONNECTOR_HTTPS_CA, pUtf8FilePath);
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
            yh_rc err = yh_set_connector_option(this.Handle, yh_connector_option.YH_CONNECTOR_PROXY_SERVER, pUtf8ProxyUrl);
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
            yh_rc err = yh_set_connector_option(this.Handle, yh_connector_option.YH_CONNECTOR_HTTPS_CERT, pUtf8FilePath);
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
            yh_rc err = yh_set_connector_option(this.Handle, yh_connector_option.YH_CONNECTOR_HTTPS_KEY, pUtf8FilePath);
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
            yh_rc err = yh_set_connector_option(this.Handle, yh_connector_option.YH_CONNECTOR_NOPROXY, pUtf8NoProxy);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Connect to the device through this connector.
    /// </summary>
    /// <param name="timeout">Connection timeout in seconds, 0 for no timeout.</param>
    public void Connect(int timeout = 0)
    {
        yh_rc err = yh_connect(this.Handle, timeout);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Sends a plaintext message to the device through this connector.
    /// </summary>
    /// <param name="request">The command to send.</param>
    /// <param name="requestData">The request data to send.</param>
    /// <param name="responseBuffer">The buffer to receive the response.</param>
    /// <returns>A tuple containing the response command and the length of the response data.</returns>
    /// <seealso cref="YubiSession.SendMessage"/> 
    public (Command response, int responseLength) SendMessage(Command request, ReadOnlySpan<byte> requestData, Span<byte> responseBuffer)
    {
        yh_rc err = yh_send_plain_msg(this.Handle, request, requestData, (nuint)requestData.Length,
            out Command responseCmd, responseBuffer, out nuint responseLen);
        YubiHsmException.ThrowIfError(err);
        return (responseCmd, (int)responseLen);
    }

    /// <summary>
    /// Creates a new session using an encryption key and MAC key derived from a password.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="password">The password to derive the keys from</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the password in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ObjectId authKeyId, ReadOnlySpan<byte> password, bool recreateSession = false)
    {
        yh_rc err = yh_create_session_derived(this.Handle, authKeyId, password, (nuint)password.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(this, sessionHandle);
    }

    /// <summary>
    /// Creates a new session using the provided encryption key and MAC key.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="encryptionKey">The encryption key</param>
    /// <param name="macKey">The MAC key</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the keys in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ObjectId authKeyId, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> macKey, bool recreateSession = false)
    {
        yh_rc err = yh_create_session(this.Handle, authKeyId, encryptionKey, (nuint)encryptionKey.Length, macKey, (nuint)macKey.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(this, sessionHandle);
    }

    /// <summary>
    /// Creates a new session using encryption keys from a platform-specific key store.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="utf8EncryptionKeyName">The name of the encryption key in the key store, UTF-8 encoded and null-terminated</param>
    /// <param name="utf8MacKeyName">The name of the MAC key in the key store, UTF-8 encoded and null-terminated</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ObjectId authKeyId, ReadOnlySpan<byte> utf8EncryptionKeyName, ReadOnlySpan<byte> utf8MacKeyName)
    {
        yh_rc err = yh_create_session_ex(this.Handle, authKeyId, utf8EncryptionKeyName, utf8MacKeyName, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(this, sessionHandle);
    }

    /// <summary>
    /// Creates a new session using an asymmetric key pair.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Asymmetric Authentication Key used to authenticate the session</param>
    /// <param name="clientPrivateKey">The private key of the client</param>
    /// <param name="devicePublicKey">The public key of the device</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSessionAsymmetric(ObjectId authKeyId, ReadOnlySpan<byte> clientPrivateKey, ReadOnlySpan<byte> devicePublicKey)
    {
        // FIXME: Is the public key parameter necessary?
        // yh_create_session_asym currently requires both the client private key and device public key,
        // but the device public key could be retrieved from the device using yh_util_get_device_pubkey.
        // Additionally, the yubihsm shell does NOT ask for the public key.
        yh_rc err = yh_create_session_asym(this.Handle, authKeyId, clientPrivateKey, (nuint)clientPrivateKey.Length, devicePublicKey, (nuint)devicePublicKey.Length, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(this, sessionHandle);
    }

    // TODO: yh_begin_create_session and yh_finish_create_session for external authentication

    /// <summary>
    /// Gets the value and algorithm of the device public key.
    /// </summary>
    /// <param name="publicKey">Buffer to store the public key value</param>
    /// <returns>A tuple containing the algorithm of the device public key and its length</returns>
    public (Algorithm algorithm, int publicKeyLength) GetDevicePublicKey(Span<byte> publicKey)
    {
        yh_rc err = yh_util_get_device_pubkey(this.Handle, publicKey, out nuint responseLen, out Algorithm alg);
        YubiHsmException.ThrowIfError(err);
        return (alg, (int)responseLen);
    }

    /// <summary>
    /// Gets device information.
    /// </summary>
    /// <returns>The device information</returns>
    public DeviceInfo GetDeviceInfo()
    {
        yh_rc err = yh_util_get_device_info_ex(this.Handle, out DeviceInfo deviceInfo);
        YubiHsmException.ThrowIfError(err);
        return deviceInfo;
    }
    // No need to expose yh_util_get_device_info since yh_util_get_device_info_ex provides a structured DeviceInfo.

    /// <summary>
    /// Gets the device version, part number (chip designator) as required by FIPS.
    /// </summary>
    /// <param name="utf8PartNumber">A buffer to store the part number (chip designator), UTF-8 encoded</param>
    /// <returns>The length of the part number</returns>
    public int GetPartNumber(Span<byte> utf8PartNumber)
    {
        yh_rc err = yh_util_get_partnumber(this.Handle, utf8PartNumber, out nuint partNumberLen);
        YubiHsmException.ThrowIfError(err);
        return (int)partNumberLen;
    }

    /// <summary>
    /// Disconnect from the device and clean up resources associated with this connector.
    /// </summary>
    public void Dispose()
    {
        this.debugFile?.Dispose();
        this.Handle.Dispose();
    }
}

internal class SafeConnectorHandle : SafeHandle
{
    private SafeModuleHandle? parent;
    private bool parentAdded;

    public SafeConnectorHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        try
        {
            yh_rc err = yh_disconnect(this.handle);
            return err == yh_rc.YHR_SUCCESS;
        }
        finally
        {
            if (this.parentAdded && this.parent is not null)
            {
                this.parent.DangerousRelease();
            }
        }
    }

    public void SetParent(SafeModuleHandle parent)
    {
        this.parent = parent;
        this.parent.DangerousAddRef(ref this.parentAdded);
    }
}