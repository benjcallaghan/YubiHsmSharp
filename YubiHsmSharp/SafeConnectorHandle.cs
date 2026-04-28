using System.Runtime.InteropServices;

namespace YubiHsmSharp;

public class SafeConnectorHandle : SafeHandle
{
    public SafeConnectorHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => throw new NotImplementedException();

    protected override bool ReleaseHandle()
    {
        throw new NotImplementedException();
    }
}