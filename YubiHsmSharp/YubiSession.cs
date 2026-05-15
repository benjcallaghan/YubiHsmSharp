namespace YubiHsmSharp;

/// <summary>
/// Represents an authenticated and encrypted session with a YubiHSM device.
/// </summary>
public sealed class YubiSession : IDisposable
{
    private readonly SafeSessionHandle handle;

    internal YubiSession(SafeSessionHandle handle)
    {
        this.handle = handle;
    }

    /// <summary>
    /// Sends an encrypted message to the device over this session.
    /// </summary>
    /// <param name="request">The command to send.</param>
    /// <param name="requestData">The request data to send.</param>
    /// <param name="responseBuffer">The buffer to receive the response.</param>
    /// <param name="responseLength">The length of the received response.</param>
    /// <returns>The response command.</returns>
    /// <seealso cref="YubiConnector.SendMessage"/>
    public Command SendMessage(Command request, ReadOnlySpan<byte> requestData, Span<byte> responseBuffer, out int responseLength)
    {
        yh_rc err = yh_send_secure_msg(this.handle, request, requestData, (nuint)requestData.Length,
            out Command responseCmd, responseBuffer, out nuint responseLen);
        YubiHsmException.ThrowIfError(err);
        responseLength = (int)responseLen;
        return responseCmd;
    }

    /// <summary>
    /// Frees data associated with the session.
    /// </summary>
    public void Dispose()
    {
        this.handle.Dispose();
    }
}

internal class SafeSessionHandle : SafeHandle
{
    public SafeSessionHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        yh_rc err = yh_destroy_session(ref this.handle);
        return err == yh_rc.YHR_SUCCESS;
    }
}