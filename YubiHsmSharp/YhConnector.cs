namespace YubiHsmSharp;

/// <summary>
/// Manages a connection to a YubiHSM device.
/// Provides connection management and device-level operations.
/// </summary>
public class YhConnector : IDisposable
{
    private IntPtr _connectorHandle;
    private bool _disposed;
    private bool _connected;

    private const string DefaultUrl = "yhusb://";

    /// <summary>
    /// Initializes a new instance of YhConnector (internal constructor).
    /// Use <see cref="Create"/> factory method instead.
    /// </summary>
    private YhConnector(IntPtr connectorHandle)
    {
        _connectorHandle = connectorHandle;
        _disposed = false;
        _connected = false;
    }

    /// <summary>
    /// Create a new connector to a YubiHSM device.
    /// </summary>
    /// <param name="url">Device URL (e.g., "yhusb://", "http://localhost:12345", "yhdebug://").
    /// Defaults to "yhusb://" for USB device discovery.</param>
    /// <returns>A new YhConnector instance.</returns>
    /// <exception cref="YubiHsmException">Thrown if connector initialization fails.</exception>
    public static YhConnector Create(string url = DefaultUrl)
    {
        // Initialize library (safe to call multiple times)
        var initResult = NativeMethods.yh_init();
        ErrorHandler.ThrowIfError(initResult, "Failed to initialize YubiHSM library");

        // Create connector
        var result = NativeMethods.yh_init_connector(url, out var connectorHandle);
        ErrorHandler.ThrowIfError(result, $"Failed to create connector to {url}");

        return new YhConnector(connectorHandle);
    }

    /// <summary>
    /// Gets whether the connector is currently connected to a device.
    /// </summary>
    public bool IsConnected => _connected;

    /// <summary>
    /// Connect to the YubiHSM device via this connector.
    /// </summary>
    /// <param name="timeoutMs">Connection timeout in milliseconds (0 = no timeout).</param>
    /// <exception cref="YubiHsmException">Thrown if connection fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public void Connect(int timeoutMs = 0)
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_connect(_connectorHandle, timeoutMs);
        ErrorHandler.ThrowIfError(result, "Failed to connect to YubiHSM device");

        _connected = true;
    }

    /// <summary>
    /// Disconnect from the YubiHSM device.
    /// </summary>
    /// <exception cref="YubiHsmException">Thrown if disconnection fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public void Disconnect()
    {
        ThrowIfDisposed();

        if (!_connected)
            return;

        var result = NativeMethods.yh_disconnect(_connectorHandle);
        ErrorHandler.ThrowIfError(result, "Failed to disconnect from YubiHSM device");

        _connected = false;
    }

    /// <summary>
    /// Get information about the connected YubiHSM device.
    /// This operation does not require an authenticated session.
    /// </summary>
    /// <returns>Device information.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public YhDeviceInfo GetDeviceInfo()
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_util_get_device_info_ex(_connectorHandle, out var deviceInfoPtr);
        ErrorHandler.ThrowIfError(result, "Failed to get device info");

        try
        {
            // Parse device info from native structure
            // This is a simplified version; actual implementation would marshal the structure properly
            var deviceInfo = MarshalDeviceInfo(deviceInfoPtr);
            return deviceInfo;
        }
        finally
        {
            if (deviceInfoPtr != IntPtr.Zero)
            {
                NativeMethods.yh_free_device_info(ref deviceInfoPtr);
            }
        }
    }

    /// <summary>
    /// List all objects on the connected device.
    /// This operation does not require an authenticated session.
    /// </summary>
    /// <returns>Array of object information for all objects on the device.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public YhObjectInfo[] ListObjects()
    {
        ThrowIfDisposed();

        const ushort maxCount = 256;
        var result = NativeMethods.yh_list_objects(_connectorHandle, maxCount, out var objectDescriptorsPtr, out var objectCount);
        ErrorHandler.ThrowIfError(result, "Failed to list objects");

        try
        {
            // Parse object descriptors from native array
            var objects = MarshalObjectDescriptors(objectDescriptorsPtr, objectCount);
            return objects;
        }
        finally
        {
            if (objectDescriptorsPtr != IntPtr.Zero)
            {
                NativeMethods.yh_free_object_descriptor(ref objectDescriptorsPtr);
            }
        }
    }

    /// <summary>
    /// Create an authenticated session using a derived key from password.
    /// </summary>
    /// <param name="authKeyId">ID of the authentication key on the device.</param>
    /// <param name="password">Password for key derivation.</param>
    /// <param name="sessionId">Requested session ID (0 = auto-assign).</param>
    /// <returns>A new authenticated YhSession.</returns>
    /// <exception cref="YubiHsmException">Thrown if session creation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public YhSession CreateSessionDerived(ushort authKeyId, string password, ushort sessionId = 0)
    {
        ThrowIfDisposed();

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var result = NativeMethods.yh_create_session_derived(
            _connectorHandle,
            authKeyId,
            password,
            (uint)passwordBytes.Length,
            sessionId,
            out var sessionHandle);

        ErrorHandler.ThrowIfError(result, "Failed to create derived session");
        return new YhSession(sessionHandle);
    }

    /// <summary>
    /// Create an authenticated session using symmetric key authentication (HMAC-SHA256).
    /// </summary>
    /// <param name="authKeyId">ID of the authentication key on the device.</param>
    /// <param name="encryptionKey">Session encryption key (typically 16 bytes).</param>
    /// <param name="macKey">Session MAC key (typically 16 bytes).</param>
    /// <param name="sessionId">Requested session ID (0 = auto-assign).</param>
    /// <returns>A new authenticated YhSession.</returns>
    /// <exception cref="YubiHsmException">Thrown if session creation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public YhSession CreateSessionSymmetric(ushort authKeyId, byte[] encryptionKey, byte[] macKey, ushort sessionId = 0)
    {
        ThrowIfDisposed();

        if (encryptionKey == null || macKey == null)
            throw new ArgumentNullException(encryptionKey == null ? nameof(encryptionKey) : nameof(macKey));

        var result = NativeMethods.yh_create_session_symmetric(
            _connectorHandle,
            authKeyId,
            encryptionKey,
            (uint)encryptionKey.Length,
            macKey,
            (uint)macKey.Length,
            sessionId,
            out var sessionHandle);

        ErrorHandler.ThrowIfError(result, "Failed to create symmetric session");
        return new YhSession(sessionHandle);
    }

    /// <summary>
    /// Begin a two-step SCP03 session creation (asymmetric authentication).
    /// This is the first step; call <see cref="FinishCreateSessionAsymmetric"/> with the context.
    /// </summary>
    /// <param name="authKeyId">ID of the authentication key on the device.</param>
    /// <param name="context">Output context for the second step.</param>
    /// <param name="cardCrypto">Card cryptographic data from device.</param>
    /// <returns>Context for <see cref="FinishCreateSessionAsymmetric"/> call.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public void BeginCreateSessionAsymmetric(ushort authKeyId, out IntPtr context, out IntPtr cardCrypto)
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_begin_create_session(_connectorHandle, authKeyId, out context, out cardCrypto);
        ErrorHandler.ThrowIfError(result, "Failed to begin asymmetric session creation");
    }

    /// <summary>
    /// Finish a two-step SCP03 session creation.
    /// </summary>
    /// <param name="context">Context from <see cref="BeginCreateSessionAsymmetric"/>.</param>
    /// <param name="sessionEncKey">Session encryption key (computed by client).</param>
    /// <param name="sessionMacKey">Session MAC key (computed by client).</param>
    /// <param name="cardCrypto">Card crypto data from device.</param>
    /// <param name="sessionId">Requested session ID (0 = auto-assign).</param>
    /// <returns>A new authenticated YhSession.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if connector is disposed.</exception>
    public YhSession FinishCreateSessionAsymmetric(
        IntPtr context,
        byte[] sessionEncKey,
        byte[] sessionMacKey,
        byte[] cardCrypto,
        ushort sessionId = 0)
    {
        ThrowIfDisposed();

        if (sessionEncKey == null || sessionMacKey == null || cardCrypto == null)
            throw new ArgumentNullException();

        var result = NativeMethods.yh_finish_create_session(
            _connectorHandle,
            context,
            sessionEncKey,
            (uint)sessionEncKey.Length,
            sessionMacKey,
            (uint)sessionMacKey.Length,
            cardCrypto,
            (uint)cardCrypto.Length,
            out var sessionHandle);

        ErrorHandler.ThrowIfError(result, "Failed to finish asymmetric session creation");
        return new YhSession(sessionHandle);
    }

    /// <summary>
    /// Dispose the connector and cleanup resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Finalizer to ensure cleanup if Dispose is not called.
    /// </summary>
    ~YhConnector()
    {
        Dispose(false);
    }

    /// <summary>
    /// Internal dispose implementation.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        try
        {
            if (_connected)
            {
                try
                {
                    Disconnect();
                }
                catch { /* Ignore errors during cleanup */ }
            }

            if (_connectorHandle != IntPtr.Zero)
            {
                var connectorRef = _connectorHandle;
                NativeMethods.yh_connector_free(ref connectorRef);
                _connectorHandle = IntPtr.Zero;
            }
        }
        finally
        {
            _disposed = true;
        }
    }

    /// <summary>
    /// Throw if connector has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(YhConnector));
    }

    #region Native Structure Marshaling

    /// <summary>
    /// Marshal device info from native structure.
    /// This is a simplified implementation; real version would handle actual struct layout.
    /// </summary>
    private static YhDeviceInfo MarshalDeviceInfo(IntPtr deviceInfoPtr)
    {
        // This is a placeholder; actual implementation would:
        // 1. Define the native struct layout
        // 2. Use Marshal.PtrToStructure or manual marshaling
        // For now, return a basic structure
        return new YhDeviceInfo
        {
            SerialNumber = 0,
            FirmwareVersion = "unknown",
            SessionsCurrent = 0,
            ObjectsMax = 256,
            ObjectsCurrent = 0,
            Capabilities = new YhCapabilities(),
            Domains = 0xFFFF,
            FipsMode = false,
            ForceAuditLog = false,
            AuditLogEntries = 0,
        };
    }

    /// <summary>
    /// Marshal object descriptors from native array.
    /// This is a simplified implementation.
    /// </summary>
    private static YhObjectInfo[] MarshalObjectDescriptors(IntPtr descriptorsPtr, ushort count)
    {
        // This is a placeholder; actual implementation would:
        // 1. Define the native struct layout
        // 2. Iterate through array and marshal each descriptor
        // For now, return empty array
        return Array.Empty<YhObjectInfo>();
    }

    #endregion
}
