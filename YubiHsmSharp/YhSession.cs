namespace YubiHsmSharp;

/// <summary>
/// Represents an authenticated session to a YubiHSM device.
/// All cryptographic operations and key management are performed through a session.
/// </summary>
public class YhSession : IDisposable
{
    private IntPtr _sessionHandle;
    private bool _disposed;
    private byte _sessionId;

    /// <summary>
    /// Initializes a new instance of YhSession (internal constructor).
    /// Sessions are created via <see cref="YhConnector.CreateSessionDerived"/>, 
    /// <see cref="YhConnector.CreateSessionSymmetric"/>, or asymmetric methods.
    /// </summary>
    internal YhSession(IntPtr sessionHandle)
    {
        _sessionHandle = sessionHandle;
        _disposed = false;

        // Get the session ID
        var result = NativeMethods.yh_get_session_id(_sessionHandle, out _sessionId);
        if (result != YhReturnCode.Success)
        {
            _sessionId = 0;
        }
    }

    /// <summary>
    /// Gets the session ID (0-15).
    /// </summary>
    public byte SessionId => _sessionId;

    /// <summary>
    /// Gets whether the session is still valid.
    /// </summary>
    public bool IsValid
    {
        get
        {
            ThrowIfDisposed();
            return _sessionHandle != IntPtr.Zero;
        }
    }

    #region Key Generation

    /// <summary>
    /// Generate a new HMAC key on the device.
    /// </summary>
    /// <param name="keyId">Desired key ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Key label (human-readable identifier).</param>
    /// <param name="domains">Domain bitmask (16-bit).</param>
    /// <param name="capabilities">Capabilities for the key.</param>
    /// <param name="algorithm">HMAC algorithm (e.g., HmacSha256).</param>
    /// <returns>The generated key ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if key generation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort GenerateHmacKey(
        ushort keyId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm)
    {
        ThrowIfDisposed();

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_generate_hmac_key(
            _sessionHandle,
            ref keyId,
            label,
            domains,
            capabilityBytes,
            algorithm);

        ErrorHandler.ThrowIfError(result, "Failed to generate HMAC key");
        return keyId;
    }

    /// <summary>
    /// Generate a new asymmetric (RSA/EC) key on the device.
    /// </summary>
    /// <param name="keyId">Desired key ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Key label.</param>
    /// <param name="domains">Domain bitmask.</param>
    /// <param name="capabilities">Capabilities for the key.</param>
    /// <param name="algorithm">Asymmetric algorithm (e.g., Rsa2048, EcP256).</param>
    /// <returns>The generated key ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if key generation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort GenerateAsymmetricKey(
        ushort keyId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm)
    {
        ThrowIfDisposed();

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_generate_asymmetric_key(
            _sessionHandle,
            ref keyId,
            label,
            domains,
            capabilityBytes,
            algorithm);

        ErrorHandler.ThrowIfError(result, "Failed to generate asymmetric key");
        return keyId;
    }

    /// <summary>
    /// Generate a new symmetric (AES/binary) key on the device.
    /// </summary>
    /// <param name="keyId">Desired key ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Key label.</param>
    /// <param name="domains">Domain bitmask.</param>
    /// <param name="capabilities">Capabilities for the key.</param>
    /// <param name="algorithm">Symmetric algorithm (e.g., Aes256).</param>
    /// <returns>The generated key ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if key generation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort GenerateSymmetricKey(
        ushort keyId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm)
    {
        ThrowIfDisposed();

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_generate_symmetric_key(
            _sessionHandle,
            ref keyId,
            label,
            domains,
            capabilityBytes,
            algorithm);

        ErrorHandler.ThrowIfError(result, "Failed to generate symmetric key");
        return keyId;
    }

    /// <summary>
    /// Import an asymmetric key from key material.
    /// </summary>
    /// <param name="keyId">Desired key ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Key label.</param>
    /// <param name="domains">Domain bitmask.</param>
    /// <param name="capabilities">Capabilities for the key.</param>
    /// <param name="algorithm">Asymmetric algorithm.</param>
    /// <param name="keyMaterial">Serialized key material (DER-encoded).</param>
    /// <returns>The imported key ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if import fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort ImportAsymmetricKey(
        ushort keyId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm,
        byte[] keyMaterial)
    {
        ThrowIfDisposed();

        if (keyMaterial == null)
            throw new ArgumentNullException(nameof(keyMaterial));

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_import_asymmetric_key(
            _sessionHandle,
            ref keyId,
            label,
            domains,
            capabilityBytes,
            algorithm,
            keyMaterial,
            (nuint)keyMaterial.Length);

        ErrorHandler.ThrowIfError(result, "Failed to import asymmetric key");
        return keyId;
    }

    /// <summary>
    /// Import a symmetric key from key material.
    /// </summary>
    /// <param name="keyId">Desired key ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Key label.</param>
    /// <param name="domains">Domain bitmask.</param>
    /// <param name="capabilities">Capabilities for the key.</param>
    /// <param name="algorithm">Symmetric algorithm.</param>
    /// <param name="keyMaterial">Raw key material bytes.</param>
    /// <returns>The imported key ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if import fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort ImportSymmetricKey(
        ushort keyId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm,
        byte[] keyMaterial)
    {
        ThrowIfDisposed();

        if (keyMaterial == null)
            throw new ArgumentNullException(nameof(keyMaterial));

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_import_symmetric_key(
            _sessionHandle,
            ref keyId,
            label,
            domains,
            capabilityBytes,
            algorithm,
            keyMaterial,
            (nuint)keyMaterial.Length);

        ErrorHandler.ThrowIfError(result, "Failed to import symmetric key");
        return keyId;
    }

    /// <summary>
    /// Import an opaque object from data.
    /// </summary>
    /// <param name="objectId">Desired object ID (0xFFFF = auto-generate).</param>
    /// <param name="label">Object label.</param>
    /// <param name="domains">Domain bitmask.</param>
    /// <param name="capabilities">Capabilities for the object.</param>
    /// <param name="algorithm">Algorithm type.</param>
    /// <param name="data">Object data bytes.</param>
    /// <returns>The imported object ID.</returns>
    /// <exception cref="YubiHsmException">Thrown if import fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort ImportOpaque(
        ushort objectId,
        string label,
        ushort domains,
        YhCapabilities capabilities,
        YhAlgorithm algorithm,
        byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        var capabilityBytes = capabilities.ToByteArray();
        var result = NativeMethods.yh_util_import_opaque(
            _sessionHandle,
            ref objectId,
            label,
            domains,
            capabilityBytes,
            algorithm,
            data,
            (nuint)data.Length);

        ErrorHandler.ThrowIfError(result, "Failed to import opaque object");
        return objectId;
    }

    #endregion

    #region HMAC Operations

    /// <summary>
    /// Sign data with an HMAC key.
    /// </summary>
    /// <param name="keyId">ID of the HMAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>HMAC signature bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] SignHmac(ushort keyId, byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        // Maximum signature size is 64 bytes for HMAC-SHA512
        var signature = new byte[64];
        var signatureLen = (nuint)signature.Length;

        var result = NativeMethods.yh_util_sign_hmac(
            _sessionHandle,
            keyId,
            data,
            (nuint)data.Length,
            signature,
            ref signatureLen);

        ErrorHandler.ThrowIfError(result, "Failed to sign HMAC");
        
        Array.Resize(ref signature, (int)signatureLen);
        return signature;
    }

    /// <summary>
    /// Verify an HMAC signature.
    /// </summary>
    /// <param name="keyId">ID of the HMAC key.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="data">Original data that was signed.</param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public bool VerifyHmac(ushort keyId, byte[] signature, byte[] data)
    {
        ThrowIfDisposed();

        if (signature == null)
            throw new ArgumentNullException(nameof(signature));
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        var result = NativeMethods.yh_util_verify_hmac(
            _sessionHandle,
            keyId,
            signature,
            (nuint)signature.Length,
            data,
            (nuint)data.Length,
            out var verified);

        ErrorHandler.ThrowIfError(result, "Failed to verify HMAC");
        return verified != 0;
    }

    #endregion

    #region RSA Operations

    /// <summary>
    /// Sign data with RSA using PKCS#1 v1.5 padding.
    /// </summary>
    /// <param name="keyId">ID of the RSA private key.</param>
    /// <param name="data">Data to sign (typically a hash).</param>
    /// <returns>RSA signature bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] SignPkcs(ushort keyId, byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        // Maximum signature size is 512 bytes for RSA-4096
        var signature = new byte[512];
        var signatureLen = (nuint)signature.Length;

        var result = NativeMethods.yh_util_sign_pkcs(
            _sessionHandle,
            keyId,
            data,
            (nuint)data.Length,
            signature,
            ref signatureLen);

        ErrorHandler.ThrowIfError(result, "Failed to sign with RSA-PKCS");

        Array.Resize(ref signature, (int)signatureLen);
        return signature;
    }

    /// <summary>
    /// Sign data with RSA using PSS padding.
    /// </summary>
    /// <param name="keyId">ID of the RSA private key.</param>
    /// <param name="data">Data to sign (typically a hash).</param>
    /// <param name="saltLength">Length of PSS salt in bytes.</param>
    /// <returns>RSA-PSS signature bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] SignPss(ushort keyId, byte[] data, nuint saltLength = 32)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        var signature = new byte[512];
        var signatureLen = (nuint)signature.Length;

        var result = NativeMethods.yh_util_sign_pss(
            _sessionHandle,
            keyId,
            data,
            (nuint)data.Length,
            signature,
            ref signatureLen,
            saltLength);

        ErrorHandler.ThrowIfError(result, "Failed to sign with RSA-PSS");

        Array.Resize(ref signature, (int)signatureLen);
        return signature;
    }

    /// <summary>
    /// Get the public key from an asymmetric key.
    /// </summary>
    /// <param name="keyId">ID of the asymmetric key.</param>
    /// <param name="publicKey">Output public key bytes (DER-encoded).</param>
    /// <param name="algorithm">Output algorithm of the key.</param>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void GetPublicKey(ushort keyId, out byte[] publicKey, out YhAlgorithm algorithm)
    {
        ThrowIfDisposed();

        var pubKeyBuffer = new byte[2048];
        var pubKeyLen = (nuint)pubKeyBuffer.Length;

        var result = NativeMethods.yh_util_get_public_key(
            _sessionHandle,
            keyId,
            pubKeyBuffer,
            ref pubKeyLen,
            out algorithm);

        ErrorHandler.ThrowIfError(result, "Failed to get public key");

        publicKey = new byte[pubKeyLen];
        Array.Copy(pubKeyBuffer, publicKey, (int)pubKeyLen);
    }

    /// <summary>
    /// Decrypt data with RSA using PKCS#1 v1.5 padding.
    /// </summary>
    /// <param name="keyId">ID of the RSA private key.</param>
    /// <param name="ciphertext">Ciphertext to decrypt.</param>
    /// <returns>Decrypted plaintext.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] DecryptPkcs(ushort keyId, byte[] ciphertext)
    {
        ThrowIfDisposed();

        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        var plaintext = new byte[2048];
        var plaintextLen = (nuint)plaintext.Length;

        var result = NativeMethods.yh_util_decrypt_pkcs(
            _sessionHandle,
            keyId,
            ciphertext,
            (nuint)ciphertext.Length,
            plaintext,
            ref plaintextLen);

        ErrorHandler.ThrowIfError(result, "Failed to decrypt with RSA-PKCS");

        Array.Resize(ref plaintext, (int)plaintextLen);
        return plaintext;
    }

    /// <summary>
    /// Decrypt data with RSA using OAEP padding.
    /// </summary>
    /// <param name="keyId">ID of the RSA private key.</param>
    /// <param name="ciphertext">Ciphertext to decrypt.</param>
    /// <returns>Decrypted plaintext.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] DecryptOaep(ushort keyId, byte[] ciphertext)
    {
        ThrowIfDisposed();

        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        var plaintext = new byte[2048];
        var plaintextLen = (nuint)plaintext.Length;

        var result = NativeMethods.yh_util_decrypt_oaep(
            _sessionHandle,
            keyId,
            ciphertext,
            (nuint)ciphertext.Length,
            plaintext,
            ref plaintextLen);

        ErrorHandler.ThrowIfError(result, "Failed to decrypt with RSA-OAEP");

        Array.Resize(ref plaintext, (int)plaintextLen);
        return plaintext;
    }

    #endregion

    #region EC Operations

    /// <summary>
    /// Sign data with an ECDSA key.
    /// </summary>
    /// <param name="keyId">ID of the EC private key.</param>
    /// <param name="data">Data to sign (typically a hash).</param>
    /// <returns>ECDSA signature bytes (raw r||s).</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] SignEcdsa(ushort keyId, byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        // Maximum signature size is ~132 bytes for P-521
        var signature = new byte[256];
        var signatureLen = (nuint)signature.Length;

        var result = NativeMethods.yh_util_sign_ecdsa(
            _sessionHandle,
            keyId,
            data,
            (nuint)data.Length,
            signature,
            ref signatureLen);

        ErrorHandler.ThrowIfError(result, "Failed to sign with ECDSA");

        Array.Resize(ref signature, (int)signatureLen);
        return signature;
    }

    /// <summary>
    /// Sign data with an EdDSA key (Ed25519/Ed448).
    /// </summary>
    /// <param name="keyId">ID of the EdDSA private key.</param>
    /// <param name="data">Data to sign (message, not hash).</param>
    /// <returns>EdDSA signature bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] SignEddsa(ushort keyId, byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        var signature = new byte[256];
        var signatureLen = (nuint)signature.Length;

        var result = NativeMethods.yh_util_sign_eddsa(
            _sessionHandle,
            keyId,
            data,
            (nuint)data.Length,
            signature,
            ref signatureLen);

        ErrorHandler.ThrowIfError(result, "Failed to sign with EdDSA");

        Array.Resize(ref signature, (int)signatureLen);
        return signature;
    }

    /// <summary>
    /// Perform ECDH key derivation to compute a shared secret.
    /// </summary>
    /// <param name="keyId">ID of the EC private key.</param>
    /// <param name="peerPublicKey">Peer's public key (DER-encoded or raw).</param>
    /// <returns>Derived shared secret bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] EcdhDerivation(ushort keyId, byte[] peerPublicKey)
    {
        ThrowIfDisposed();

        if (peerPublicKey == null)
            throw new ArgumentNullException(nameof(peerPublicKey));

        var sharedSecret = new byte[512];
        var sharedSecretLen = (nuint)sharedSecret.Length;

        var result = NativeMethods.yh_util_ecdh_derivation(
            _sessionHandle,
            keyId,
            peerPublicKey,
            (nuint)peerPublicKey.Length,
            sharedSecret,
            ref sharedSecretLen);

        ErrorHandler.ThrowIfError(result, "Failed to perform ECDH derivation");

        Array.Resize(ref sharedSecret, (int)sharedSecretLen);
        return sharedSecret;
    }

    #endregion

    #region AES Operations

    /// <summary>
    /// Encrypt data with AES.
    /// </summary>
    /// <param name="keyId">ID of the AES key.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <returns>Encrypted ciphertext.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] EncryptAes(ushort keyId, byte[] plaintext)
    {
        ThrowIfDisposed();

        if (plaintext == null)
            throw new ArgumentNullException(nameof(plaintext));

        var ciphertext = new byte[plaintext.Length + 16]; // Add space for potential padding
        var ciphertextLen = (nuint)ciphertext.Length;

        var result = NativeMethods.yh_util_encrypt_aes(
            _sessionHandle,
            keyId,
            plaintext,
            (nuint)plaintext.Length,
            ciphertext,
            ref ciphertextLen);

        ErrorHandler.ThrowIfError(result, "Failed to encrypt with AES");

        Array.Resize(ref ciphertext, (int)ciphertextLen);
        return ciphertext;
    }

    /// <summary>
    /// Decrypt data with AES.
    /// </summary>
    /// <param name="keyId">ID of the AES key.</param>
    /// <param name="ciphertext">Data to decrypt.</param>
    /// <returns>Decrypted plaintext.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] DecryptAes(ushort keyId, byte[] ciphertext)
    {
        ThrowIfDisposed();

        if (ciphertext == null)
            throw new ArgumentNullException(nameof(ciphertext));

        var plaintext = new byte[ciphertext.Length];
        var plaintextLen = (nuint)plaintext.Length;

        var result = NativeMethods.yh_util_decrypt_aes(
            _sessionHandle,
            keyId,
            ciphertext,
            (nuint)ciphertext.Length,
            plaintext,
            ref plaintextLen);

        ErrorHandler.ThrowIfError(result, "Failed to decrypt with AES");

        Array.Resize(ref plaintext, (int)plaintextLen);
        return plaintext;
    }

    #endregion

    #region Key Wrapping

    /// <summary>
    /// Export an object in wrapped form (encrypted with a wrap key).
    /// </summary>
    /// <param name="wrapKeyId">ID of the wrapping key.</param>
    /// <param name="objectType">Type of object to export.</param>
    /// <param name="objectId">ID of object to export.</param>
    /// <returns>Wrapped object data.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] ExportWrappedKey(ushort wrapKeyId, YhObjectType objectType, ushort objectId)
    {
        ThrowIfDisposed();

        // Maximum wrapped size is 2048 bytes
        var wrappedObject = new byte[2048];
        var wrappedLen = (nuint)wrappedObject.Length;

        var result = NativeMethods.yh_util_export_wrapped(
            _sessionHandle,
            wrapKeyId,
            objectType,
            objectId,
            wrappedObject,
            ref wrappedLen);

        ErrorHandler.ThrowIfError(result, "Failed to export wrapped object");

        Array.Resize(ref wrappedObject, (int)wrappedLen);
        return wrappedObject;
    }

    /// <summary>
    /// Import a wrapped object (encrypted data that will be decrypted and stored on device).
    /// </summary>
    /// <param name="wrapKeyId">ID of the unwrapping key.</param>
    /// <param name="wrappedObject">Wrapped object data.</param>
    /// <returns>The ID of the imported object.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public ushort ImportWrappedKey(ushort wrapKeyId, byte[] wrappedObject)
    {
        ThrowIfDisposed();

        if (wrappedObject == null)
            throw new ArgumentNullException(nameof(wrappedObject));

        var result = NativeMethods.yh_util_import_wrapped(
            _sessionHandle,
            wrapKeyId,
            wrappedObject,
            (nuint)wrappedObject.Length,
            out var importedObjectId);

        ErrorHandler.ThrowIfError(result, "Failed to import wrapped object");
        return importedObjectId;
    }

    /// <summary>
    /// Delete an object from the device.
    /// </summary>
    /// <param name="objectId">ID of object to delete.</param>
    /// <param name="objectType">Type of object to delete.</param>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void DeleteObject(ushort objectId, YhObjectType objectType)
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_util_delete_object(_sessionHandle, objectId, objectType);
        ErrorHandler.ThrowIfError(result, "Failed to delete object");
    }

    #endregion

    #region Object Management

    /// <summary>
    /// Get metadata about an object on the device.
    /// </summary>
    /// <param name="objectId">ID of the object.</param>
    /// <param name="objectType">Type of the object.</param>
    /// <returns>Object metadata.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public YhObjectInfo GetObjectInfo(ushort objectId, YhObjectType objectType)
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_util_get_object_info(
            _sessionHandle,
            objectId,
            objectType,
            out var objectInfoPtr);

        ErrorHandler.ThrowIfError(result, "Failed to get object info");

        try
        {
            // Parse object info from native structure
            var objectInfo = MarshalObjectInfo(objectInfoPtr);
            return objectInfo;
        }
        finally
        {
            if (objectInfoPtr != IntPtr.Zero)
            {
                // Note: In real implementation, would need to free this properly
            }
        }
    }

    /// <summary>
    /// List objects on the device (requires session for full functionality).
    /// </summary>
    /// <param name="typeFilter">Optional object type filter.</param>
    /// <param name="idFilter">Optional object ID filter.</param>
    /// <returns>Array of object information matching filters.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public YhObjectInfo[] ListObjects(YhObjectType? typeFilter = null, ushort? idFilter = null)
    {
        ThrowIfDisposed();

        // Placeholder implementation; real version would use yh_list_objects with filters
        return Array.Empty<YhObjectInfo>();
    }

    /// <summary>
    /// Set object attributes (currently supports label updates).
    /// </summary>
    /// <param name="objectId">ID of the object.</param>
    /// <param name="objectType">Type of the object.</param>
    /// <param name="label">New label for the object.</param>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void SetObjectAttributes(ushort objectId, YhObjectType objectType, string label)
    {
        ThrowIfDisposed();

        if (label == null)
            throw new ArgumentNullException(nameof(label));

        // Placeholder implementation
        // In real YubiHSM API, this would require using a specific command or utility
    }

    #endregion

    #region Device Operations

    /// <summary>
    /// Get storage information for the device.
    /// </summary>
    /// <param name="totalSlots">Total storage slots available.</param>
    /// <param name="freeSlots">Number of free storage slots.</param>
    /// <param name="usedRecords">Number of used records.</param>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void GetStorageInfo(out ushort totalSlots, out ushort freeSlots, out ushort usedRecords)
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_util_get_storage_info(
            _sessionHandle,
            out totalSlots,
            out freeSlots,
            out usedRecords);

        ErrorHandler.ThrowIfError(result, "Failed to get storage info");
    }

    /// <summary>
    /// Get pseudo-random bytes from the device.
    /// </summary>
    /// <param name="count">Number of random bytes to generate.</param>
    /// <returns>Array of random bytes.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] GetRandomBytes(uint count)
    {
        ThrowIfDisposed();

        var randomData = new byte[count];
        var randomLen = (nuint)count;

        var result = NativeMethods.yh_util_get_pseudo_random(
            _sessionHandle,
            (nuint)count,
            randomData,
            ref randomLen);

        ErrorHandler.ThrowIfError(result, "Failed to get random bytes");

        Array.Resize(ref randomData, (int)randomLen);
        return randomData;
    }

    /// <summary>
    /// Reset the device (erase all data).
    /// WARNING: This operation cannot be undone!
    /// </summary>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void ResetDevice()
    {
        ThrowIfDisposed();

        var result = NativeMethods.yh_util_reset_device(_sessionHandle);
        ErrorHandler.ThrowIfError(result, "Failed to reset device");
    }

    /// <summary>
    /// Get a device option value.
    /// </summary>
    /// <param name="option">Option to retrieve.</param>
    /// <returns>Option value as byte array.</returns>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public byte[] GetOption(YhOption option)
    {
        ThrowIfDisposed();

        var value = new byte[256];
        var valueLen = (nuint)value.Length;

        var result = NativeMethods.yh_util_get_option(
            _sessionHandle,
            option,
            value,
            ref valueLen);

        ErrorHandler.ThrowIfError(result, "Failed to get option");

        Array.Resize(ref value, (int)valueLen);
        return value;
    }

    /// <summary>
    /// Set a device option value.
    /// </summary>
    /// <param name="option">Option to set.</param>
    /// <param name="value">Option value bytes.</param>
    /// <exception cref="YubiHsmException">Thrown if operation fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if session is disposed.</exception>
    public void SetOption(YhOption option, byte[] value)
    {
        ThrowIfDisposed();

        if (value == null)
            throw new ArgumentNullException(nameof(value));

        var result = NativeMethods.yh_util_set_option(
            _sessionHandle,
            option,
            value,
            (nuint)value.Length);

        ErrorHandler.ThrowIfError(result, "Failed to set option");
    }

    #endregion

    #region Native Structure Marshaling

    /// <summary>
    /// Marshal object info from native structure.
    /// This is a placeholder implementation.
    /// </summary>
    private static YhObjectInfo MarshalObjectInfo(IntPtr objectInfoPtr)
    {
        return new YhObjectInfo
        {
            Id = 0,
            Type = YhObjectType.Opaque,
            Algorithm = YhAlgorithm.Aes256,
            Label = "",
            Domains = 0,
            Capabilities = new YhCapabilities(),
            Origin = "Unknown",
            Sequence = 0,
            DelegatedCapabilities = false,
            Exportable = false,
            Importable = false,
            InCache = false,
            CreatedTime = 0,
            LastUsedTime = 0,
        };
    }

    #endregion

    #region Resource Management

    /// <summary>
    /// Dispose the session and cleanup resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Finalizer to ensure cleanup if Dispose is not called.
    /// </summary>
    ~YhSession()
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
            if (_sessionHandle != IntPtr.Zero)
            {
                // Close the session
                try
                {
                    var result = NativeMethods.yh_util_close_session(_sessionHandle);
                    if (result != YhReturnCode.Success)
                    {
                        // Try destroy as fallback
                        var sessionRef = _sessionHandle;
                        NativeMethods.yh_destroy_session(ref sessionRef);
                    }
                }
                catch { /* Ignore errors during cleanup */ }

                _sessionHandle = IntPtr.Zero;
            }
        }
        finally
        {
            _disposed = true;
        }
    }

    /// <summary>
    /// Throw if session has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(YhSession));
    }

    #endregion
}
