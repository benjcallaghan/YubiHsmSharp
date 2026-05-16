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
    /// Lists objects accessible from the session
    /// </summary>
    /// <param name="objects">The buffer to receive the object descriptors.</param>
    /// <param name="objectsLength">The number of objects returned.</param>
    /// <param name="id">The ID of the object to list (0 for all).</param>
    /// <param name="type">The type of the object to list (0 for all).</param>
    /// <param name="domains">The domains of the object to list (0 for all).</param>
    /// <param name="capabilities">The capabilities of the object to list (default for all).</param>
    /// <param name="algorithm">The algorithm of the object to list (0 for all).</param>
    /// <param name="label">The label of the object to list (default for all).</param>
    public void ListObjects(
        Span<ObjectDescriptor> objects,
        out int objectsLength,
        ushort id = 0,
        ObjectType type = 0,
        ushort domains = 0,
        in Capabilities capabilities = default,
        Algorithm algorithm = 0,
        ReadOnlySpan<byte> label = default)
    {
        yh_rc err = yh_util_list_objects(this.handle, id, type, domains, in capabilities, algorithm, label, objects, out nuint n_objects);
        YubiHsmException.ThrowIfError(err);
        objectsLength = (int)n_objects;
    }

    /// <summary>
    /// Gets metadata of the object with the given ID and type.
    /// </summary>
    /// <param name="id">The ID of the object to retrieve.</param>
    /// <param name="type">The type of the object to retrieve.</param>
    /// <returns>The metadata of the object.</returns>
    public ObjectDescriptor GetObject(ushort id, ObjectType type)
    {
        yh_rc err = yh_util_get_object_info(this.handle, id, type, out ObjectDescriptor desc);
        YubiHsmException.ThrowIfError(err);
        return desc;
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