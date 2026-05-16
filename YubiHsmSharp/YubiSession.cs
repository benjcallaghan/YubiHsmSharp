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
        Domains domains = default,
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
    /// Gets the value of the public key with the given ID.
    /// </summary>
    /// <param name="id">The ID of the public key to retrieve.</param>
    /// <param name="publicKey">The buffer to receive the public key value.</param>
    /// <param name="publicKeyLength">The length of the received public key.</param>
    /// <returns>The algorithm of the public key.</returns>
    public Algorithm GetPublicKey(ushort id, Span<byte> publicKey, out int publicKeyLength)
    {
        yh_rc err = yh_util_get_public_key(this.handle, id, publicKey, out nuint publicKeyLen, out Algorithm algorithm);
        YubiHsmException.ThrowIfError(err);
        publicKeyLength = (int)publicKeyLen;
        return algorithm;
    }

    /// <summary>
    /// Gets the value of the public key with the given ID and type.
    /// </summary>
    /// <param name="type">The type of the public key to retrieve.</param>
    /// <param name="id">The ID of the public key to retrieve.</param>
    /// <param name="publicKey">The buffer to receive the public key value.</param>
    /// <param name="publicKeyLength">The length of the received public key.</param>
    /// <returns>The algorithm of the public key.</returns>
    public Algorithm GetPublicKey(ObjectType type, ushort id, Span<byte> publicKey, out int publicKeyLength)
    {
        yh_rc err = yh_util_get_public_key_ex(this.handle, type, id, publicKey, out nuint publicKeyLen, out Algorithm algorithm);
        YubiHsmException.ThrowIfError(err);
        publicKeyLength = (int)publicKeyLen;
        return algorithm;
    }

    /// <summary>
    /// Signs data using RSA-PKCS#1v1.5
    /// </summary>
    /// <remarks>
    /// <paramref name="data"/> is either a raw hashed message (sha1, sha256, sha384, or sha512)
    /// or that with correct digestinfo pre-pended.
    /// </remarks>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="hashed">true if the data is only hashed; otherwise, false.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <param name="signatureLength">The length of the received signature.</param>
    public void SignPkcs1v15(ushort keyId, bool hashed, ReadOnlySpan<byte> data, Span<byte> signature, out int signatureLength)
    {
        yh_rc err = yh_util_sign_pkcs1v1_5(this.handle, keyId, hashed, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        signatureLength = (int)signatureLen;
    }

    /// <summary>
    /// Signs data using RSA-PSS
    /// </summary>
    /// <remarks>
    /// <paramref name="data"/> is a raw hashed message (sha1, sha256, sha384, or sha512).
    /// </remarks>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <param name="signatureLength">The length of the received signature.</param>
    /// <param name="saltLength">The length of the salt.</param>
    /// <param name="maskGenerationFunction">The algorithm for mask generation.</param>
    public void SignPss(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature, out int signatureLength,
        int saltLength, Algorithm maskGenerationFunction)
    {
        yh_rc err = yh_util_sign_pss(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen,
            (nuint)saltLength, maskGenerationFunction);
        YubiHsmException.ThrowIfError(err);
        signatureLength = (int)signatureLen;
    }

    /// <summary>
    /// Signs data using ECDSA 
    /// </summary>
    /// <remarks>
    /// <paramref name="data"/> is a raw hashed message, a truncated hash to the curve length, or a padded hash to the curve length.
    /// </remarks>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <param name="signatureLength">The length of the received signature.</param>
    public void SignEcdsa(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature, out int signatureLength)
    {
        yh_rc err = yh_util_sign_ecdsa(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        signatureLength = (int)signatureLen;
    }

    /// <summary>
    /// Signs data using EdDSA
    /// </summary>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <param name="signatureLength">The length of the received signature.</param>
    public void SignEddsa(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature, out int signatureLength)
    {
        yh_rc err = yh_util_sign_eddsa(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        signatureLength = (int)signatureLen;
    }

    /// <summary>
    /// Signs data using HMAC
    /// </summary>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <param name="signatureLength">The length of the received signature.</param>
    public void SignHmac(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature, out int signatureLength)
    {
        yh_rc err = yh_util_sign_hmac(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        signatureLength = (int)signatureLen;
    }

    /// <summary>
    /// Get a fixed number of psuedo-random bytes from the device.
    /// </summary>
    /// <param name="random">The buffer to receive the random bytes.</param>
    /// <param name="randomLength">The length of the received random bytes.</param>
    public void GetPseudoRandom(Span<byte> random, out int randomLength)
    {
        yh_rc err = yh_util_get_pseudo_random(this.handle, (nuint)random.Length, random, out nuint randomLen);
        YubiHsmException.ThrowIfError(err);
        randomLength = (int)randomLen;
    }

    /// <summary>
    /// Imports an AES key into the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="key">The key data.</param>
    /// <param name="keyId">The ID of the key to import. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportAesKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_aes_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, key);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports an RSA key into the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="p">P component of the RSA key.</param>
    /// <param name="q">Q component of the RSA key.</param>
    /// <param name="keyId">The ID of the key to import. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportRsaKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_rsa_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, p, q);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports an Elliptic Curve key into the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="key">The key data.</param>
    /// <param name="keyId">The ID of the key to import. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportECKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_ec_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, key);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports an ED key into the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="key">The key data.</param>
    /// <param name="keyId">The ID of the key to import. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportEDKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_ed_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, key);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports an HMAC key into the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="key">The key data.</param>
    /// <param name="keyId">The ID of the key to import. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportHmacKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_hmac_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, key, (nuint)key.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
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
        yh_rc err = yh_util_close_session(this.handle);
        if (err != yh_rc.YHR_SUCCESS)
        {
            return false;
        }

        err = yh_destroy_session(ref this.handle);
        return err == yh_rc.YHR_SUCCESS;
    }
}