namespace YubiHsmSharp;

internal class SafeSessionHandle : SafeHandle
{
    public SafeSessionHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => throw new NotImplementedException();

    protected override bool ReleaseHandle()
    {
        throw new NotImplementedException();
    }
}