using System.Diagnostics;

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
    /// Gets or sets the status of Force Audit mode, which prevents the device from performing
    /// additional operations when the log store is full.
    /// </summary>
    public DeviceOption ForceAudit
    {
        get
        {
            Span<byte> option = stackalloc byte[1];
            yh_rc err = yh_util_get_option(this.handle, yh_option.YH_OPTION_FORCE_AUDIT, option, out nuint optionLen);
            YubiHsmException.ThrowIfError(err);
            Debug.Assert(optionLen == 1);
            return (DeviceOption)option[0];
        }
        set
        {
            Span<byte> option = [(byte)value];
            yh_rc err = yh_util_set_option(this.handle, yh_option.YH_OPTION_FORCE_AUDIT, 1, option);
            YubiHsmException.ThrowIfError(err);
        }
    }

    // TODO: Command Audit
    // TODO: Algorithm Toggle

    /// <summary>
    /// Gets or sets the status of FIPS mode. Changing this value can only be done on an empty YubiHSM 2.
    /// </summary>
    public DeviceOption FipsMode
    {
        get
        {
            Span<byte> option = stackalloc byte[1];
            yh_rc err = yh_util_get_option(this.handle, yh_option.YH_OPTION_FIPS_MODE, option, out nuint optionLen);
            YubiHsmException.ThrowIfError(err);
            Debug.Assert(optionLen == 1);
            return (DeviceOption)option[0];
        }
        set
        {
            Span<byte> option = [(byte)value];
            yh_rc err = yh_util_set_option(this.handle, yh_option.YH_OPTION_FIPS_MODE, 1, option);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Gets the session ID.
    /// </summary>
    public byte SessionId
    {
        get
        {
            yh_rc err = yh_get_session_id(this.handle, out byte sessionId);
            YubiHsmException.ThrowIfError(err);
            return sessionId;
        }
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
        ReadOnlySpan<sbyte> label = default)
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
    public ushort ImportAesKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
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
    public ushort ImportRsaKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, ushort keyId = 0)
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
    public ushort ImportECKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
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
    public ushort ImportEDKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
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
    public ushort ImportHmacKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ReadOnlySpan<byte> key, ushort keyId = 0)
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
    public ushort GenerateAesKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
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
    public ushort GenerateRsaKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
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
    public ushort GenerateECKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
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
    public ushort GenerateEDKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
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
    public ushort GenerateHmacKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities, Algorithm algorithm, ushort keyId = 0)
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
    public ushort PutRsaWrappedKey(ushort wrapKeyId, ObjectType targetType, Algorithm algorithm, ReadOnlySpan<sbyte> label,
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
    public ushort ImportWrapKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
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
    public ushort ImportPublicWrapKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
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
    public ushort GenerateWrapKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
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
    public ushort ImportOpaque(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
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
    public (ushort objectId, int importLength) ImportOpaque(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, ReadOnlySpan<byte> opaque, CompressOption compression, ushort objectId = 0)
    {
        yh_rc err = yh_util_import_opaque_ex(this.handle, ref objectId, label, domains, in capabilities,
            algorithm, opaque, (nuint)opaque.Length, compression, out nuint importLen);
        YubiHsmException.ThrowIfError(err);
        return (objectId, (int)importLen);
    }

    /// <summary>
    /// Signs an SSH Certificate request. This function produces a signature that can then be used to produce the certificate.
    /// </summary>
    /// <param name="keyId">The ID of the key used to sign the request.</param>
    /// <param name="templateId">The ID of the template to use as a certificate template.</param>
    /// <param name="signatureAlgorithm">The signature algorithm to use.</param>
    /// <param name="certificateRequest">The certificate request to sign.</param>
    /// <param name="signature">The buffer to store the generated signature.</param>
    /// <returns>The length of the generated signature.</returns>
    public int SignSshCertificate(ushort keyId, ushort templateId, Algorithm signatureAlgorithm,
        ReadOnlySpan<byte> certificateRequest, Span<byte> signature)
    {
        yh_rc err = yh_util_sign_ssh_certificate(this.handle, keyId, templateId, signatureAlgorithm,
            certificateRequest, (nuint)certificateRequest.Length, signature, out nuint signatureLen);
        YubiHsmException.ThrowIfError(err);
        return (int)signatureLen;
    }

    /// <summary>
    /// Imports an <see cref="ObjectType.AuthenticationKey"/> into the device.
    /// </summary>
    /// <param name="label">The label of the authentication key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the authentication key.</param>
    /// <param name="delegataedCapabilities">The delegated capabilities of the authentication key.</param>
    /// <param name="encryptionKey">The buffer containing the encryption key to import.</param>
    /// <param name="macKey">The buffer containing the MAC key to import.</param>
    /// <param name="keyId">The ID of the authentication key. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported authentication key.</returns>
    public ushort ImportAuthenticationKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        in Capabilities delegataedCapabilities, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> macKey, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_authentication_key(this.handle, ref keyId, label, domains, in capabilities,
            in delegataedCapabilities, encryptionKey, (nuint)encryptionKey.Length, macKey, (nuint)macKey.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Imports an <see cref="ObjectType.AuthenticationKey"/> into the device, with the encryption and MAC keys derived from a password.
    /// </summary>
    /// <param name="label">The label of the authentication key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the key belongs.</param>
    /// <param name="capabilities">The capabilities of the authentication key.</param>
    /// <param name="delegataedCapabilities">The delegated capabilities of the authentication key.</param>
    /// <param name="password">The password from which to derive the encryption and MAC keys.</param>
    /// <param name="keyId">The ID of the authentication key. 0 if the ID should be assigned by the device.</param>
    /// <returns>The ID of the imported authentication key.</returns>
    public ushort ImportAuthenticationKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        in Capabilities delegataedCapabilities, ReadOnlySpan<byte> password, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_authentication_key_derived(this.handle, ref keyId, label, domains, in capabilities,
            in delegataedCapabilities, password, (nuint)password.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Replaces the long lived encryption key and MAC key associated with an <see cref="ObjectType.AuthenticationKey"/>.
    /// </summary>
    /// <param name="keyId">The ID of the authentication key to change.</param>
    /// <param name="encryptionKey">The buffer containing the new encryption key.</param>
    /// <param name="macKey">The buffer containing the new MAC key.</param>
    /// <returns>The ID of the changed authentication key.</returns>
    public ushort ChangeAuthenticationKey(ushort keyId, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> macKey)
    {
        yh_rc err = yh_util_change_authentication_key(this.handle, ref keyId,
            encryptionKey, (nuint)encryptionKey.Length, macKey, (nuint)macKey.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Replaces the long lived encryption key and MAC key associated with an <see cref="ObjectType.AuthenticationKey"/> with keys derived from a password.
    /// </summary>
    /// <param name="keyId">The ID of the authentication key to change.</param>
    /// <param name="password">The password from which to derive the new encryption and MAC keys.</param>
    /// <returns>The ID of the changed authentication key.</returns>
    public ushort ChangeAuthenticationKey(ushort keyId, ReadOnlySpan<byte> password)
    {
        yh_rc err = yh_util_change_authentication_key_derived(this.handle, ref keyId, password, (nuint)password.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Gets a <see cref="ObjectType.Template"/> from the device.
    /// </summary>
    /// <param name="templateId">The ID of the template to retrieve.</param>
    /// <param name="template">The buffer to store the retrieved template.</param>
    /// <returns>The length of the retrieved template.</returns>
    public int GetTemplate(ushort templateId, Span<byte> template)
    {
        yh_rc err = yh_util_get_template(this.handle, templateId, template, out nuint templateLen);
        YubiHsmException.ThrowIfError(err);
        return (int)templateLen;
    }

    /// <summary>
    /// Imports a <see cref="ObjectType.Template"/> into the device.
    /// </summary>
    /// <param name="label">The label for the template, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains to which the template belongs.</param>
    /// <param name="capabilities">The capabilities associated with the template.</param>
    /// <param name="algorithm">The algorithm used by the template.</param>
    /// <param name="template">The buffer containing the template data.</param>
    /// <param name="templateId">The ID of the template to import.</param>
    /// <returns>The ID of the imported template.</returns>
    public ushort ImportTemplate(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, ReadOnlySpan<byte> template, ushort templateId = 0)
    {
        yh_rc err = yh_util_import_template(this.handle, ref templateId, label, domains,
            in capabilities, algorithm, template, (nuint)template.Length);
        YubiHsmException.ThrowIfError(err);
        return templateId;
    }

    /// <summary>
    /// Creates a Yubico OTP AEAD using the provided data.
    /// </summary>
    /// <param name="keyId">The ID of the key to use.</param>
    /// <param name="key">The OTP key.</param>
    /// <param name="privateId">The OTP private ID.</param>
    /// <param name="aead">The buffer to store the created AEAD.</param>
    /// <returns>The length of the created AEAD.</returns>
    public int CreateOtpAead(ushort keyId, ReadOnlySpan<byte> key, ReadOnlySpan<byte> privateId, Span<byte> aead)
    {
        yh_rc err = yh_util_create_otp_aead(this.handle, keyId, key, privateId, aead, out nuint aeadLen);
        YubiHsmException.ThrowIfError(err);
        return (int)aeadLen;
    }

    /// <summary>
    /// Creates an OTP AEAD from random data.
    /// </summary>
    /// <param name="keyId">The ID of the key to use.</param>
    /// <param name="aead">The buffer to store the created AEAD.</param>
    /// <returns>The length of the created AEAD.</returns>
    public int RandomizeOtpAead(ushort keyId, Span<byte> aead)
    {
        yh_rc err = yh_util_randomize_otp_aead(this.handle, keyId, aead, out nuint aeadLen);
        YubiHsmException.ThrowIfError(err);
        return (int)aeadLen;
    }

    /// <summary>
    /// Decrypts a Yubico OTP and returns counters and time information.
    /// </summary>
    /// <param name="keyId">The ID of the key to use.</param>
    /// <param name="aead">The AEAD as created by <see cref="CreateOtpAead"/> or <see cref="RandomizeOtpAead"/>.</param>
    /// <param name="otp">The OTP to decrypt.</param>
    /// <returns>The decrypted counters and time information.</returns>
    public OtpCounters DecryptOtp(ushort keyId, ReadOnlySpan<byte> aead, ReadOnlySpan<byte> otp)
    {
        yh_rc err = yh_util_decrypt_otp(this.handle, keyId, aead, (nuint)aead.Length, otp,
            out ushort useCtr, out byte sessionCtr, out byte tstph, out ushort tstpl);
        YubiHsmException.ThrowIfError(err);
        return new OtpCounters(useCtr, sessionCtr, tstph, tstpl);
    }

    /// <summary>
    /// Rewraps an OTP AEAD from one <see cref="ObjectType.OtpAeadKey"/> to another.
    /// </summary>
    /// <param name="fromId">The ID of the source key.</param>
    /// <param name="toId">The ID of the destination key.</param>
    /// <param name="fromAead">The AEAD to rewrap.</param>
    /// <param name="toAead">The buffer to store the rewrapped AEAD.</param>
    /// <returns>The length of the rewrapped AEAD.</returns>
    public int RewrapOtpAead(ushort fromId, ushort toId, ReadOnlySpan<byte> fromAead, Span<byte> toAead)
    {
        yh_rc err = yh_util_rewrap_otp_aead(this.handle, fromId, toId, fromAead, (nuint)fromAead.Length, toAead, out nuint toAeadLen);
        YubiHsmException.ThrowIfError(err);
        return (int)toAeadLen;
    }

    /// <summary>
    /// Imports an <see cref="ObjectType.OtpAeadKey"/> used for Yubico OTP Decryption.
    /// </summary>
    /// <param name="label">The label for the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains for the key.</param>
    /// <param name="capabilities">The capabilities for the key.</param>
    /// <param name="nonceId">The nonce ID for the key.</param>
    /// <param name="key">The key data.</param>
    /// <param name="keyId">The ID of the key. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the imported key.</returns>
    public ushort ImportOtpAeadKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        ushort nonceId, ReadOnlySpan<byte> key, ushort keyId = 0)
    {
        yh_rc err = yh_util_import_otp_aead_key(this.handle, ref keyId, label, domains, in capabilities,
            nonceId, key, (nuint)key.Length);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Generates an <see cref="ObjectType.OtpAeadKey"/> used for Yubico OTP Decryption in the device.
    /// </summary>
    /// <param name="label">The label for the key, UTF-8 encoded and null-terminated.</param>
    /// <param name="domains">The domains for the key.</param>
    /// <param name="capabilities">The capabilities for the key.</param>
    /// <param name="algorithm">The algorithm for the key.</param>
    /// <param name="nonceId">The nonce ID for the key.</param>
    /// <param name="keyId">The ID of the key. 0 if the ID should be generated by the device.</param>
    /// <returns>The ID of the generated key.</returns>
    public ushort GenerateOtpAeadKey(ReadOnlySpan<sbyte> label, Domains domains, in Capabilities capabilities,
        Algorithm algorithm, ushort nonceId, ushort keyId = 0)
    {
        yh_rc err = yh_util_generate_otp_aead_key(this.handle, ref keyId, label, domains, in capabilities, algorithm, nonceId);
        YubiHsmException.ThrowIfError(err);
        return keyId;
    }

    /// <summary>
    /// Gets attestation of an Asymmetric Key in the form of an X.509 certificate.
    /// </summary>
    /// <param name="keyId">The ID of the Asymmetric Key to attest.</param>
    /// <param name="attestationId">The ID of the key used to sign the attestation.</param>
    /// <param name="certificate">The buffer to store the generated certificate.</param>
    /// <returns>The length of the generated certificate.</returns>
    public int SignAttestationCertificate(ushort keyId, ushort attestationId, Span<byte> certificate)
    {
        yh_rc err = yh_util_sign_attestation_certificate(this.handle, keyId, attestationId, certificate, out nuint certLen);
        YubiHsmException.ThrowIfError(err);
        return (int)certLen;
    }

    /// <summary>
    /// Reports currently free storage.
    /// </summary>
    /// <returns>Information about the free storage.</returns>
    public StorageInfo GetStorageInfo()
    {
        yh_rc err = yh_util_get_storage_info(this.handle, out ushort totalRecords, out ushort freeRecords,
            out ushort totalPages, out ushort freePages, out ushort pageSize);
        YubiHsmException.ThrowIfError(err);
        return new StorageInfo(totalRecords, freeRecords, totalPages, freePages, pageSize);
    }

    /// <summary>
    /// Encrypts (wraps) data using a <see cref="ObjectType.WrapKey"/>.
    /// </summary>
    /// <param name="keyId">The ID of the wrap key.</param>
    /// <param name="data">The data to wrap.</param>
    /// <param name="wrappedData">The buffer to store the wrapped data.</param>
    /// <returns>The length of the wrapped data.</returns>
    public int WrapData(ushort keyId, ReadOnlySpan<byte> data, Span<byte> wrappedData)
    {
        yh_rc err = yh_util_wrap_data(this.handle, keyId, data, (nuint)data.Length, wrappedData, out nuint wrappedDataLen);
        YubiHsmException.ThrowIfError(err);
        return (int)wrappedDataLen;
    }

    /// <summary>
    /// Decrypts (unwraps) data using a <see cref="ObjectType.WrapKey"/>.
    /// </summary>
    /// <param name="keyId">The ID of the wrap key.</param>
    /// <param name="wrappedData">The data to unwrap.</param>
    /// <param name="data">The buffer to store the unwrapped data.</param>
    /// <returns>The length of the unwrapped data.</returns>
    public int UnwrapData(ushort keyId, ReadOnlySpan<byte> wrappedData, Span<byte> data)
    {
        yh_rc err = yh_util_unwrap_data(this.handle, keyId, wrappedData, (nuint)wrappedData.Length, data, out nuint dataLen);
        YubiHsmException.ThrowIfError(err);
        return (int)dataLen;
    }

    /// <summary>
    /// Encrypts data using an AES <see cref="ObjectType.SymmetricKey"/> in ECB mode.
    /// </summary>
    /// <param name="keyId">The ID of the AES key.</param>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="ciphertext">The buffer to store the encrypted data.</param>
    /// <returns>The length of the encrypted data.</returns>
    public int EncryptAesEcb(ushort keyId, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        yh_rc err = yh_util_encrypt_aes_ecb(this.handle, keyId, plaintext, (nuint)plaintext.Length, ciphertext, out nuint ciphertextLen);
        YubiHsmException.ThrowIfError(err);
        return (int)ciphertextLen;
    }

    /// <summary>
    /// Decrypts data using an AES <see cref="ObjectType.SymmetricKey"/> in ECB mode.
    /// </summary>
    /// <param name="keyId">The ID of the AES key.</param>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="plaintext">The buffer to store the decrypted data.</param>
    /// <returns>The length of the decrypted data.</returns>
    public int DecryptAesEcb(ushort keyId, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        yh_rc err = yh_util_decrypt_aes_ecb(this.handle, keyId, ciphertext, (nuint)ciphertext.Length, plaintext, out nuint plaintextLen);
        YubiHsmException.ThrowIfError(err);
        return (int)plaintextLen;
    }

    /// <summary>
    /// Encrypt data using an AES <see cref="ObjectType.SymmetricKey"/> in CBC mode.
    /// </summary>
    /// <param name="keyId">The ID of the AES key.</param>
    /// <param name="iv">The 16-byte initialization vector.</param>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="ciphertext">The buffer to store the encrypted data.</param>
    /// <returns>The length of the encrypted data.</returns>
    public int EncryptAesCbc(ushort keyId, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        yh_rc err = yh_util_encrypt_aes_cbc(this.handle, keyId, iv, plaintext, (nuint)plaintext.Length,
            ciphertext, out nuint ciphertextLen);
        YubiHsmException.ThrowIfError(err);
        return (int)ciphertextLen;
    }

    /// <summary>
    /// Decrypt data using an AES <see cref="ObjectType.SymmetricKey"/> in CBC mode.
    /// </summary>
    /// <param name="keyId">The ID of the AES key.</param>
    /// <param name="iv">The 16-byte initialization vector.</param>
    /// <param name="ciphertext">The data to decrypt.</param>
    /// <param name="plaintext">The buffer to store the decrypted data.</param>
    /// <returns>The length of the decrypted data.</returns>
    public int DecryptAesCbc(ushort keyId, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        yh_rc err = yh_util_decrypt_aes_cbc(this.handle, keyId, iv, ciphertext, (nuint)ciphertext.Length,
            plaintext, out nuint plaintextLen);
        YubiHsmException.ThrowIfError(err);
        return (int)plaintextLen;
    }

    /// <summary>
    /// Blink the LED of the device to identify it.
    /// </summary>
    /// <param name="duration">The duration for which to blink the LED.</param>
    public void BlinkDevice(TimeSpan duration)
    {
        yh_rc err = yh_util_blink_device(this.handle, (byte)duration.TotalSeconds);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Factory reset the device. Resets and reboots the device, deletes all Objects
    /// and restores the default <see cref="ObjectType.AuthenticationKey"/>.
    /// </summary>
    public void ResetDevice()
    {
        yh_rc err = yh_util_reset_device(this.handle);
        YubiHsmException.ThrowIfError(err);
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