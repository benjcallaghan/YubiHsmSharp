namespace YubiHsmSharp;

/// <summary>
/// Represents the YubiHSM module. This class should be instantiated once per application,
/// and should be disposed when the application is finished using the module.
/// </summary>
public class YubiModule : IDisposable
{
    private readonly SafeModuleHandle handle;

    /// <summary>
    /// Initializes the YubiHSM module.
    /// </summary>
    public YubiModule()
    {
        yh_rc err = yh_init();
        YubiHsmException.ThrowIfError(err);
        this.handle = new SafeModuleHandle();
    }

    /// <summary>
    /// Initializes a connection to a YubiHSM device using the specified URL.
    /// </summary>
    /// <param name="utf8Url">The URL associated with this connector, encoded as UTF-8 and null-terminated.</param>
    /// <returns>A <see cref="YubiConnector"/> configured with the provided URL.</returns>
    public YubiConnector InitConnector(ReadOnlySpan<byte> utf8Url)
    {
        yh_rc err = yh_init_connector(utf8Url, out SafeConnectorHandle handle);
        YubiHsmException.ThrowIfError(err);
        return new YubiConnector(handle);
    }

    /// <summary>
    /// Cleans up the YubiHSM module.
    /// </summary>
    public void Dispose()
    {
        this.handle.Dispose();
    }

    // There is never an actual handle here. We're just relying on the cleanup of SafeHandle.
    private class SafeModuleHandle : SafeHandle
    {
        public SafeModuleHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => false;

        protected override bool ReleaseHandle()
        {
            yh_rc err = yh_exit();
            return err == yh_rc.YHR_SUCCESS;
        }
    }
}