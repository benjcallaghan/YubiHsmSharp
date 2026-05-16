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
    /// <returns>A tuple containing the response command and its length.</returns>
    /// <seealso cref="YubiConnector.SendMessage"/>
    public (Command response, int responseLength) SendMessage(Command request, ReadOnlySpan<byte> requestData, Span<byte> responseBuffer)
    {
        yh_rc err = yh_send_secure_msg(this.handle, request, requestData, (nuint)requestData.Length,
            out Command responseCmd, responseBuffer, out nuint responseLen);
        YubiHsmException.ThrowIfError(err);
        return (responseCmd, (int)responseLen);
    }

    /// <summary>
    /// Lists objects accessible from the session
    /// </summary>
    /// <param name="objects">The buffer to receive the object descriptors.</param>
    /// <param name="id">The ID of the object to list (0 for all).</param>
    /// <param name="type">The type of the object to list (0 for all).</param>
    /// <param name="domains">The domains of the object to list (0 for all).</param>
    /// <param name="capabilities">The capabilities of the object to list (default for all).</param>
    /// <param name="algorithm">The algorithm of the object to list (0 for all).</param>
    /// <param name="label">The label of the object to list (default for all).</param>
    /// <returns>The number of objects returned.</returns>
    public int ListObjects(
        Span<ObjectDescriptor> objects,
        ushort id = 0,
        ObjectType type = 0,
        Domains domains = default,
        in Capabilities capabilities = default,
        Algorithm algorithm = 0,
        ReadOnlySpan<byte> label = default)
    {
        yh_rc err = yh_util_list_objects(this.handle, id, type, domains, in capabilities, algorithm, label, objects, out nuint n_objects);
        YubiHsmException.ThrowIfError(err);
        return (int)n_objects;
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
    /// <returns>A tuple containing the algorithm of the public key and its length.</returns>
    public (Algorithm algorithm, int publicKeyLength) GetPublicKey(ushort id, Span<byte> publicKey)
    {
        yh_rc err = yh_util_get_public_key(this.handle, id, publicKey, out nuint publicKeyLen, out Algorithm algorithm);
        YubiHsmException.ThrowIfError(err);
        return (algorithm, (int)publicKeyLen);
    }

    /// <summary>
    /// Gets the value of the public key with the given ID and type.
    /// </summary>
    /// <param name="type">The type of the public key to retrieve.</param>
    /// <param name="id">The ID of the public key to retrieve.</param>
    /// <param name="publicKey">The buffer to receive the public key value.</param>
    /// <returns>A tuple containing the algorithm of the public key and its length.</returns>
    public (Algorithm algorithm, int publicKeyLength) GetPublicKey(ObjectType type, ushort id, Span<byte> publicKey)
    {
        yh_rc err = yh_util_get_public_key_ex(this.handle, type, id, publicKey, out nuint publicKeyLen, out Algorithm algorithm);
        YubiHsmException.ThrowIfError(err);
        return (algorithm, (int)publicKeyLen);
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
    /// <returns>The length of the signature.</returns>
    public int SignPkcs1v15(ushort keyId, bool hashed, ReadOnlySpan<byte> data, Span<byte> signature)
    {
        yh_rc err = yh_util_sign_pkcs1v1_5(this.handle, keyId, hashed, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
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
    /// <param name="saltLength">The length of the salt.</param>
    /// <param name="maskGenerationFunction">The algorithm for mask generation.</param>
    /// <returns>The length of the signature.</returns>
    public int SignPss(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature,
        int saltLength, Algorithm maskGenerationFunction)
    {
        yh_rc err = yh_util_sign_pss(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen,
            (nuint)saltLength, maskGenerationFunction);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
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
    /// <returns>The length of the signature.</returns>
    public int SignEcdsa(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature)
    {
        yh_rc err = yh_util_sign_ecdsa(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
    }

    /// <summary>
    /// Signs data using EdDSA
    /// </summary>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <returns>The length of the signature.</returns>
    public int SignEddsa(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature)
    {
        yh_rc err = yh_util_sign_eddsa(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
    }

    /// <summary>
    /// Signs data using HMAC
    /// </summary>
    /// <param name="keyId">The ID of the signing key.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="signature">The buffer to receive the signature.</param>
    /// <returns>The length of the signature.</returns>
    public int SignHmac(ushort keyId, ReadOnlySpan<byte> data, Span<byte> signature)
    {
        yh_rc err = yh_util_sign_hmac(this.handle, keyId, data, (nuint)data.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
    }

    /// <summary>
    /// Get a fixed number of psuedo-random bytes from the device.
    /// </summary>
    /// <param name="random">The buffer to receive the random bytes.</param>
    /// <returns>The length of the received random bytes.</returns>
    public int GetPseudoRandom(Span<byte> random)
    {
        yh_rc err = yh_util_get_pseudo_random(this.handle, (nuint)random.Length, random, out nuint randomLen);
        YubiHsmException.ThrowIfError(err);
        return (int)randomLen;
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
    /// Generates an AES key in the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="keyId">The ID of the key to generate. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateAesKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_aes_key(this.handle, ref keyId, label, domains, in capabilities, algorithm);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates an RSA key in the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="keyId">The ID of the key to generate. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateRsaKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_rsa_key(this.handle, ref keyId, label, domains, in capabilities, algorithm);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates an Elliptic Curve key in the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="keyId">The ID of the key to generate. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateECKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_ec_key(this.handle, ref keyId, label, domains, in capabilities, algorithm);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates an ED key in the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="keyId">The ID of the key to generate. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateEDKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_ed_key(this.handle, ref keyId, label, domains, in capabilities, algorithm);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates an HMAC key in the device.
    /// </summary>
    /// <param name="label">Label of the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="algorithm">The algorithm of the key.</param>
    /// <param name="keyId">The ID of the key to generate. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateHmacKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_hmac_key(this.handle, ref keyId, label, domains, in capabilities, algorithm);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Verifies an HMAC signature.
    /// </summary>
    /// <param name="keyId">The ID of the HMAC key to use.</param>
    /// <param name="signature">The HMAC signature to verify.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>true if the signature is valid, false otherwise.</returns>
    public bool VerifyHmac(ushort keyId, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data)
    {
        yh_rc err = yh_util_verify_hmac(this.handle, keyId, signature, (nuint)signature.Length, data, (nuint)data.Length, out bool verified);
        YubiHsmException.ThrowIfError(err);
        return verified;
    }

    /// <summary>
    /// Decrypts data using RSA-PKCS#1v1.5
    /// </summary>
    /// <param name="keyId">The ID of the RSA key to use.</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="plaintext">The buffer to store the decrypted plaintext.</param>
    /// <returns>The length of the decrypted plaintext.</returns>
    public int DecryptPkcs1v15(ushort keyId, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        yh_rc err = yh_util_decrypt_pkcs1v1_5(this.handle, keyId, ciphertext, (nuint)ciphertext.Length, plaintext, out nuint plaintextLen);
        YubiHsmException.ThrowIfError(err);
        return (int)plaintextLen;
    }

    /// <summary>
    /// Decrypts data using RSA-OAEP
    /// </summary>
    /// <param name="keyId">The ID of the RSA key to use.</param>
    /// <param name="ciphertext">The ciphertext to decrypt.</param>
    /// <param name="plaintext">The buffer to store the decrypted plaintext.</param>
    /// <param name="label">Hash of OAEP label.</param>
    /// <param name="maskGenerationFunction">The algorithm for generating the mask.</param>
    /// <returns>The length of the decrypted plaintext.</returns>
    public int DecryptOaep(ushort keyId, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> label, Algorithm maskGenerationFunction)
    {
        yh_rc err = yh_util_decrypt_oaep(this.handle, keyId, ciphertext, (nuint)ciphertext.Length, plaintext, out nuint plaintextLen, label, (nuint)label.Length, maskGenerationFunction);
        YubiHsmException.ThrowIfError(err);
        return (int)plaintextLen;
    }

    /// <summary>
    /// Derives a shared secret using ECDH key agreement.
    /// </summary>
    /// <param name="keyId">The ID of the EC private key to use.</param>
    /// <param name="publicKey">The public key for the ECDH agreement.</param>
    /// <param name="sharedSecret">The buffer to store the derived shared secret.</param>
    /// <returns>The length of the derived shared secret.</returns>
    public int DeriveEcdh(ushort keyId, ReadOnlySpan<byte> publicKey, Span<byte> sharedSecret)
    {
        yh_rc err = yh_util_derive_ecdh(this.handle, keyId, publicKey, (nuint)publicKey.Length, sharedSecret, out nuint sharedSecretLen);
        YubiHsmException.ThrowIfError(err);
        return (int)sharedSecretLen;
    }

    /// <summary>
    /// Deletes an object with the given ID and type.
    /// </summary>
    /// <param name="id">The ID of the object to delete.</param>
    /// <param name="type">The type of the object to delete.</param>
    public void DeleteObject(ushort id, ObjectType type)
    {
        yh_rc err = yh_util_delete_object(this.handle, id, type);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Exports an object with the given ID and type wrapped by a wrapping key.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="targetType">The type of the object to export.</param>
    /// <param name="targetId">The ID of the object to export.</param>
    /// <param name="wrappedKey">The buffer to store the wrapped key.</param>
    /// <returns>The length of the wrapped key.</returns>
    /// <seealso cref="ImportWrapped"/>
    public int ExportWrapped(ushort wrapKeyId, ObjectType targetType, ushort targetId, Span<byte> wrappedKey)
    {
        yh_rc err = yh_util_export_wrapped(this.handle, wrapKeyId, targetType, targetId, wrappedKey, out nuint wrappedKeyLen);
        YubiHsmException.ThrowIfError(err);
        return (int)wrappedKeyLen;
    }

    /// <summary>
    /// Exports an object with the given ID and type wrapped by a wrapping key, with an option to include the ED25519 seed.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="targetType">The type of the object to export.</param>
    /// <param name="targetId">The ID of the object to export.</param>
    /// <param name="includeSeed">A value indicating whether to include the ED25519 seed.</param>
    /// <param name="wrappedKey">The buffer to store the wrapped key.</param>
    /// <returns>The length of the wrapped key.</returns>
    /// <seealso cref="ImportWrapped"/>
    public int ExportWrapped(ushort wrapKeyId, ObjectType targetType, ushort targetId, bool includeSeed, Span<byte> wrappedKey)
    {
        yh_rc err = yh_util_export_wrapped_ex(this.handle, wrapKeyId, targetType, targetId, includeSeed, wrappedKey, out nuint wrappedKeyLen);
        YubiHsmException.ThrowIfError(err);
        return (int)wrappedKeyLen;
    }

    /// <summary>
    /// Import a wrapped object into the device.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="wrappedKey">The buffer containing the wrapped key.</param>
    /// <returns>A tuple containing the type and ID of the imported object.</returns>
    /// <seealso cref="ExportWrapped(ushort, ObjectType, ushort, bool, Span{byte})"/>
    public (ObjectType targetType, ushort targetId) ImportWrapped(ushort wrapKeyId, ReadOnlySpan<byte> wrappedKey)
    {
        yh_rc err = yh_util_import_wrapped(this.handle, wrapKeyId, wrappedKey, (nuint)wrappedKey.Length, out ObjectType targetType, out ushort targetId);
        YubiHsmException.ThrowIfError(err);
        return (targetType, targetId);
    }

    /// <summary>
    /// Exports key material using an RSA wrap key. Metadata is not included. Only asymmetric and symmetric key objects are valid targets.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="targetType">The type of the object to export.</param>
    /// <param name="targetId">The ID of the object to export.</param>
    /// <param name="aes">The (ephemeral) AES algorithm to use.</param>
    /// <param name="hash">The hash algorithm to use.</param>
    /// <param name="maskGenerationFunction">The mask generation function to use.</param>
    /// <param name="oaepLabel">The OAEP label.</param>
    /// <param name="wrappedKey">The buffer to store the wrapped key.</param>
    /// <returns>The length of the wrapped key.</returns>
    /// <seealso cref="PutRsaWrappedKey"/> 
    public int GetRsaWrappedKey(ushort wrapKeyId, ObjectType targetType, ushort targetId,
        Algorithm aes, Algorithm hash, Algorithm maskGenerationFunction, ReadOnlySpan<byte> oaepLabel, Span<byte> wrappedKey)
    {
        yh_rc err = yh_util_get_rsa_wrapped_key(this.handle, wrapKeyId, targetType, targetId,
            aes, hash, maskGenerationFunction, oaepLabel, (nuint)oaepLabel.Length, wrappedKey, out nuint wrappedKeyLen);
        YubiHsmException.ThrowIfError(err);
        return (int)wrappedKeyLen;
    }

    /// <summary>
    /// Exports an object using an RSA wrap key. The wrapped object contains all metadata.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="targetType">The type of the object to export.</param>
    /// <param name="targetId">The ID of the object to export.</param>
    /// <param name="aes">The (ephemeral) AES algorithm to use.</param>
    /// <param name="hash">The hash algorithm to use.</param>
    /// <param name="maskGenerationFunction">The mask generation function to use.</param>
    /// <param name="oaepLabel">The OAEP label.</param>
    /// <param name="wrappedKey">The buffer to store the wrapped key.</param>
    /// <returns>The length of the wrapped key.</returns>
    /// <seealso cref="ImportRsaWrapped"/> 
    public int ExportRsaWrapped(ushort wrapKeyId, ObjectType targetType, ushort targetId,
        Algorithm aes, Algorithm hash, Algorithm maskGenerationFunction, ReadOnlySpan<byte> oaepLabel, Span<byte> wrappedKey)
    {
        yh_rc err = yh_util_export_rsa_wrapped(this.handle, wrapKeyId, targetType, targetId,
            aes, hash, maskGenerationFunction, oaepLabel, (nuint)oaepLabel.Length, wrappedKey, out nuint wrappedKeyLen);
        YubiHsmException.ThrowIfError(err);
        return (int)wrappedKeyLen;
    }

    /// <summary>
    /// Imports an object using an RSA wrap key.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="hash">The hash algorithm to use.</param>
    /// <param name="maskGenerationFunction">The mask generation function to use.</param>
    /// <param name="oaepLabel">The OAEP label.</param>
    /// <param name="wrappedKey">The buffer containing the wrapped key.</param>
    /// <returns>A tuple containing the type and ID of the imported object.</returns>
    /// <seealso cref="ExportRsaWrapped"/>
    public (ObjectType targetType, ushort targetId) ImportRsaWrapped(ushort wrapKeyId,
        Algorithm hash, Algorithm maskGenerationFunction, ReadOnlySpan<byte> oaepLabel, ReadOnlySpan<byte> wrappedKey)
    {
        yh_rc err = yh_util_import_rsa_wrapped(this.handle, wrapKeyId,
            hash, maskGenerationFunction, oaepLabel, (nuint)oaepLabel.Length, wrappedKey, (nuint)wrappedKey.Length,
            out ObjectType targetType, out ushort targetId);
        YubiHsmException.ThrowIfError(err);
        return (targetType, targetId);
    }

    /// <summary>
    /// Imports key material using an RSA wrap key.
    /// </summary>
    /// <param name="wrapKeyId">The ID of the wrapping key to use.</param>
    /// <param name="targetType">The type of the object to import.</param>
    /// <param name="algorithm">The algorithm of the object to import.</param>
    /// <param name="label">The label for the object.</param>
    /// <param name="domains">The domains to which the object belongs.</param>
    /// <param name="capabilities">The capabilities of the object.</param>
    /// <param name="hash">The hash algorithm to use.</param>
    /// <param name="maskGenerationFunction">The mask generation function to use.</param>
    /// <param name="oaepLabel">The OAEP label.</param>
    /// <param name="wrappedKey">The buffer containing the wrapped key.</param>
    /// <param name="targetId">The ID of the object to import. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported object.</returns>
    /// <seealso cref="GetRsaWrappedKey"/>
    public ushort PutRsaWrappedKey(ushort wrapKeyId, ObjectType targetType, Algorithm algorithm, ReadOnlySpan<byte> label,
        Domains domains, in Capabilities capabilities, Algorithm hash, Algorithm maskGenerationFunction,
        ReadOnlySpan<byte> oaepLabel, ReadOnlySpan<byte> wrappedKey, ushort targetId = 0)
    {
        yh_rc err = yh_util_put_rsa_wrapped_key(this.handle, wrapKeyId, targetType, ref targetId, algorithm,
            label, domains, in capabilities, hash, maskGenerationFunction, oaepLabel, (nuint)oaepLabel.Length,
            wrappedKey, (nuint)wrappedKey.Length);
        YubiHsmException.ThrowIfError(err);
        return targetId;
    }

    /// <summary>
    /// Imports a Wrap Key into the device.
    /// </summary>
    /// <param name="label">The label for the wrap key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the wrap key belongs.</param>
    /// <param name="capabilities">The capabilities of the wrap key.</param>
    /// <param name="algorithm">The algorithm of the wrap key.</param>
    /// <param name="delegatedCapabilities">The delegated capabilities of the wrap key.</param>
    /// <param name="key">The buffer containing the wrap key material.</param>
    /// <param name="keyId">The ID of the wrap key. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported wrap key.</returns>
    public ushort ImportWrapKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, in Capabilities delegatedCapabilities, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_wrap_key(this.handle, ref keyId, label, domains, in capabilities,
            algorithm, in delegatedCapabilities, key, (nuint)key.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports a public RSA key as a Public Wrap Key into the device.
    /// </summary>
    /// <param name="label">The label for the public wrap key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the public wrap key belongs.</param>
    /// <param name="capabilities">The capabilities of the public wrap key.</param>
    /// <param name="algorithm">The algorithm of the public wrap key.</param>
    /// <param name="delegatedCapabilities">The delegated capabilities of the public wrap key.</param>
    /// <param name="key">The buffer containing the public wrap key material.</param>
    /// <param name="keyId">The ID of the public wrap key. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported public wrap key.</returns>
    public ushort ImportPublicWrapKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, in Capabilities delegatedCapabilities, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_public_wrap_key(this.handle, ref keyId, label, domains, in capabilities,
            algorithm, in delegatedCapabilities, key, (nuint)key.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates a Wrap Key in the device.
    /// </summary>
    /// <param name="label">The label for the wrap key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the wrap key belongs.</param>
    /// <param name="capabilities">The capabilities of the wrap key.</param>
    /// <param name="algorithm">The algorithm of the wrap key.</param>
    /// <param name="delegatedCapabilities">The delegated capabilities of the wrap key.</param>
    /// <param name="keyId">The ID of the wrap key. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the generated wrap key.</returns>
    public ushort GenerateWrapKey(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, in Capabilities delegatedCapabilities, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_wrap_key(this.handle, ref keyId, label, domains, in capabilities,
            algorithm, in delegatedCapabilities);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Get audit logs from the device.
    /// </summary>
    /// <remarks>
    /// When audit enforce is set, if the log buffer is full, no new operations (other than authentication operations)
    /// can be performed unless the log entries are read by this command and then the log index is set by calling
    /// <see cref="SetLogIndex"/>.
    /// </remarks>
    /// <param name="logs">The buffer to store the log entries.</param>
    /// <returns>A tuple containing the number of unlogged boot entries, unlogged authentication entries, and the length of the logs.</returns>
    public (ushort unloggedBoot, ushort unloggedAuth, int logsLength) GetLogEntries(Span<LogEntry> logs)
    {
        yh_rc err = yh_util_get_log_entries(this.handle, out ushort unloggedBoot, out ushort unloggedAuth, logs, out nuint logsLen);
        YubiHsmException.ThrowIfError(err);
        return (unloggedBoot, unloggedAuth, (int)logsLen);
    }

    /// <summary>
    /// Set the index of the last extracted log entry.
    /// </summary>
    /// <remarks>
    /// This function should be called after <see cref="GetLogEntries"/> to inform the device what the last
    /// extracted log entry is so new logs can be written. This is used when forced auditing is enabled.
    /// </remarks>
    /// <param name="index">The index of the last extracted log entry.</param>
    public void SetLogIndex(ushort index)
    {
        yh_rc err = yh_util_set_log_index(this.handle, index);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Gets an <see cref="ObjectType.Opaque"/> object (like an X.509 certificate) from the device.
    /// </summary>
    /// <param name="objectId">The ID of the opaque object to retrieve.</param>
    /// <param name="opaque">The buffer to store the retrieved opaque object.</param>
    /// <returns>The length of the retrieved opaque object.</returns>
    public int GetOpaque(ushort objectId, Span<byte> opaque)
    {
        yh_rc err = yh_util_get_opaque(this.handle, objectId, opaque, out nuint dataLen);
        YubiHsmException.ThrowIfError(err);
        return (int)dataLen;
    }

    /// <summary>
    /// Gets an <see cref="ObjectType.Opaque"/> object (like an X.509 certificate) from the device, with an option to try decompressing the object if it's stored in compressed form.
    /// </summary>
    /// <param name="objectId">The ID of the opaque object to retrieve.</param>
    /// <param name="opaque">The buffer to store the retrieved opaque object.</param>
    /// <param name="tryDecompress">A value indicating whether to try decompressing the object if it's stored in compressed form.</param>
    /// <returns>A tuple containing the length of the retrieved opaque object and the length of the stored object.</returns>
    public (int dataLength, int storedLength) GetOpaque(ushort objectId, Span<byte> opaque, bool tryDecompress)
    {
        yh_rc err = yh_util_get_opaque_ex(this.handle, objectId, opaque, out nuint dataLen, out nuint storedLen, tryDecompress);
        YubiHsmException.ThrowIfError(err);
        return ((int)dataLen, (int)storedLen);
    }

    /// <summary>
    /// Imports an <see cref="ObjectType.Opaque"/> object into the device.
    /// </summary>
    /// <param name="label">The label of the opaque object, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains where the opaque object will be operating within.</param>
    /// <param name="capabilities">The capabilities of the opaque object.</param>
    /// <param name="algorithm">The algorithm of the opaque object.</param>
    /// <param name="opaque">The buffer containing the opaque object to import.</param>
    /// <param name="objectId">The ID of the opaque object. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported opaque object.</returns>
    public ushort ImportOpaque(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, ReadOnlySpan<byte> opaque, ushort objectId = 0)
    {
        yh_rc err = yh_util_import_opaque(this.handle, ref objectId, label, domains, in capabilities,
            algorithm, opaque, (nuint)opaque.Length);
        YubiHsmException.ThrowIfError(err);
        return objectId;
    }

    /// <summary>
    /// Imports an <see cref="ObjectType.Opaque"/> object into the device, with an option to compress the object before storing it.
    /// </summary>
    /// <param name="label">The label of the opaque object, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains where the opaque object will be operating within.</param>
    /// <param name="capabilities">The capabilities of the opaque object.</param>
    /// <param name="algorithm">The algorithm of the opaque object.</param>
    /// <param name="opaque">The buffer containing the opaque object to import.</param>
    /// <param name="compression">The compression option for the opaque object.</param>
    /// <param name="objectId">The ID of the opaque object. 0 if the ID should be assigned by the device.</param>
    /// <returns>A tuple containing the ID of the imported opaque object and the length of the imported object.</returns>
    public (ushort objectId, int importLength) ImportOpaque(ReadOnlySpan<byte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, ReadOnlySpan<byte> opaque, CompressOption compression, ushort objectId = 0)
    {
        yh_rc err = yh_util_import_opaque_ex(this.handle, ref objectId, label, domains, in capabilities,
            algorithm, opaque, (nuint)opaque.Length, compression, out nuint importLen);
        YubiHsmException.ThrowIfError(err);
        return (objectId, (int)importLen);
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