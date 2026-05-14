using System.Runtime.InteropServices;
using static YubiHsmSharp.yubihsm;

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