namespace YubiHsmSharp;

/// <summary>
/// P/Invoke declarations for libyubihsm C library functions.
/// All methods are internal; public API uses managed wrappers.
/// See: https://github.com/Yubico/yubihsm-shell/blob/main/include/yubihsm.h
/// </summary>
internal static class NativeMethods
{
    private const string LibraryName = AssemblyInfo.NativeLibrary;
    private const CallingConvention CallingConv = CallingConvention.Cdecl;

    #region Library Initialization

    /// <summary>
    /// Initialize the YubiHSM library.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_init();

    /// <summary>
    /// Clean up and exit the YubiHSM library.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern void yh_exit();

    #endregion

    #region Connector Management

    /// <summary>
    /// Initialize a connector to a YubiHSM device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_init_connector(
        [MarshalAs(UnmanagedType.LPStr)] string url,
        out IntPtr connector);

    /// <summary>
    /// Connect to a YubiHSM device via the connector.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_connect(IntPtr connector, int timeout);

    /// <summary>
    /// Disconnect from a YubiHSM device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_disconnect(IntPtr connector);

    /// <summary>
    /// Clean up and free a connector.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern void yh_connector_free(ref IntPtr connector);

    /// <summary>
    /// Set connector option.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_set_connector_option(
        IntPtr connector,
        YhConnectorOption option,
        [MarshalAs(UnmanagedType.LPStr)] string value);

    #endregion

    #region Session Management

    /// <summary>
    /// Create a session with derived session keys from a password.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_create_session_derived(
        IntPtr connector,
        ushort authKeyId,
        [MarshalAs(UnmanagedType.LPStr)] string password,
        uint passwordLength,
        ushort sessionId,
        out IntPtr session);

    /// <summary>
    /// Create a session with symmetric key authentication.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_create_session_symmetric(
        IntPtr connector,
        ushort authKeyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] encKey,
        uint encKeyLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] macKey,
        uint macKeyLen,
        ushort sessionId,
        out IntPtr session);

    /// <summary>
    /// Begin SCP03 session creation (first step).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_begin_create_session(
        IntPtr connector,
        ushort authKeyId,
        out IntPtr context,
        out IntPtr cardCrypto);

    /// <summary>
    /// Finish SCP03 session creation (second step).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_finish_create_session(
        IntPtr connector,
        IntPtr context,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] sessionEncKey,
        uint sessionEncKeyLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] sessionMacKey,
        uint sessionMacKeyLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] cardCrypto,
        uint cardCryptoLen,
        out IntPtr session);

    /// <summary>
    /// Destroy and cleanup a session.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_destroy_session(ref IntPtr session);

    /// <summary>
    /// Get the session ID from a session object.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_get_session_id(IntPtr session, out byte sessionId);

    #endregion

    #region Device Information & Management

    /// <summary>
    /// Get device information (pre-authentication).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_device_info(
        IntPtr connector,
        out IntPtr deviceInfo);

    /// <summary>
    /// Get extended device information.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_device_info_ex(
        IntPtr connector,
        out IntPtr deviceInfo);

    /// <summary>
    /// Free device info structure.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern void yh_free_device_info(ref IntPtr deviceInfo);

    /// <summary>
    /// Get storage information.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_storage_info(
        IntPtr session,
        out ushort storageTotal,
        out ushort storageFree,
        out ushort storageUsedRecords);

    /// <summary>
    /// Reset the device (erase all data).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_reset_device(IntPtr session);

    #endregion

    #region Object Management

    /// <summary>
    /// List objects on the device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_list_objects(
        IntPtr connector,
        ushort maxCount,
        out IntPtr objectDescriptors,
        out ushort objectCount);

    /// <summary>
    /// Get object metadata.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_object_info(
        IntPtr session,
        ushort objectId,
        YhObjectType objectType,
        out IntPtr objectInfo);

    /// <summary>
    /// Delete an object from the device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_delete_object(
        IntPtr session,
        ushort objectId,
        YhObjectType objectType);

    /// <summary>
    /// Free object descriptor list.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern void yh_free_object_descriptor(ref IntPtr objectDescriptors);

    #endregion

    #region Key Generation

    /// <summary>
    /// Generate an HMAC key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_generate_hmac_key(
        IntPtr session,
        ref ushort keyId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm);

    /// <summary>
    /// Generate an asymmetric (RSA/EC) key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_generate_asymmetric_key(
        IntPtr session,
        ref ushort keyId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm);

    /// <summary>
    /// Generate a symmetric (AES/binary) key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_generate_symmetric_key(
        IntPtr session,
        ref ushort keyId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm);

    /// <summary>
    /// Import an asymmetric key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_import_asymmetric_key(
        IntPtr session,
        ref ushort keyId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] keyData,
        nuint keyDataLen);

    /// <summary>
    /// Import a symmetric key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_import_symmetric_key(
        IntPtr session,
        ref ushort keyId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] keyData,
        nuint keyDataLen);

    /// <summary>
    /// Import an opaque object.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_import_opaque(
        IntPtr session,
        ref ushort objectId,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        ushort domains,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        YhAlgorithm algorithm,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7)] byte[] data,
        nuint dataLen);

    #endregion

    #region HMAC Operations

    /// <summary>
    /// Sign data with HMAC.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_sign_hmac(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] data,
        nuint dataLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] signature,
        ref nuint signatureLen);

    /// <summary>
    /// Verify HMAC signature.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_verify_hmac(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] signature,
        nuint signatureLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] data,
        nuint dataLen,
        out byte verified);

    #endregion

    #region RSA Operations

    /// <summary>
    /// Sign data with RSA (PKCS#1 v1.5).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_sign_pkcs(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] data,
        nuint dataLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] signature,
        ref nuint signatureLen);

    /// <summary>
    /// Sign data with RSA-PSS.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_sign_pss(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] data,
        nuint dataLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] signature,
        ref nuint signatureLen,
        nuint saltLen);

    /// <summary>
    /// Get public key from an asymmetric key.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_public_key(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] publicKey,
        ref nuint publicKeyLen,
        out YhAlgorithm algorithm);

    /// <summary>
    /// Decrypt data with RSA (PKCS#1 v1.5).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_decrypt_pkcs(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] ciphertext,
        nuint ciphertextLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] plaintext,
        ref nuint plaintextLen);

    /// <summary>
    /// Decrypt data with RSA-OAEP.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_decrypt_oaep(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] ciphertext,
        nuint ciphertextLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] plaintext,
        ref nuint plaintextLen);

    #endregion

    #region EC Operations

    /// <summary>
    /// Sign data with ECDSA.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_sign_ecdsa(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] data,
        nuint dataLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] signature,
        ref nuint signatureLen);

    /// <summary>
    /// Sign data with EdDSA.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_sign_eddsa(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] data,
        nuint dataLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] signature,
        ref nuint signatureLen);

    /// <summary>
    /// Derive ECDH shared secret.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_ecdh_derivation(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] peerPublicKey,
        nuint peerPublicKeyLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] sharedSecret,
        ref nuint sharedSecretLen);

    #endregion

    #region AES Operations

    /// <summary>
    /// Encrypt data with AES.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_encrypt_aes(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] plaintext,
        nuint plaintextLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] ciphertext,
        ref nuint ciphertextLen);

    /// <summary>
    /// Decrypt data with AES.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_decrypt_aes(
        IntPtr session,
        ushort keyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] ciphertext,
        nuint ciphertextLen,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] plaintext,
        ref nuint plaintextLen);

    #endregion

    #region Key Wrapping

    /// <summary>
    /// Export a wrapped object.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_export_wrapped(
        IntPtr session,
        ushort wrapKeyId,
        YhObjectType objectType,
        ushort objectId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] wrappedObject,
        ref nuint wrappedObjectLen);

    /// <summary>
    /// Import a wrapped object.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_import_wrapped(
        IntPtr session,
        ushort wrapKeyId,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] wrappedObject,
        nuint wrappedObjectLen,
        out ushort importedObjectId);

    #endregion

    #region Device Options & Random

    /// <summary>
    /// Get a device option value.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_option(
        IntPtr session,
        YhOption option,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] value,
        ref nuint valueLen);

    /// <summary>
    /// Set a device option value.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_set_option(
        IntPtr session,
        YhOption option,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] value,
        nuint valueLen);

    /// <summary>
    /// Get pseudo-random bytes from the device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_get_pseudo_random(
        IntPtr session,
        nuint length,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] randomData,
        ref nuint randomDataLen);

    #endregion

    #region Raw Commands (Advanced)

    /// <summary>
    /// Send a secure (encrypted) message to the device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_send_secure_msg(
        IntPtr session,
        YhCommand command,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] command_data,
        nuint command_data_len,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] response,
        ref nuint response_len);

    /// <summary>
    /// Send a plain (unencrypted) message to the device.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_send_plain_msg(
        IntPtr connector,
        YhCommand command,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] command_data,
        nuint command_data_len,
        [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] response,
        ref nuint response_len);

    #endregion

    #region String Conversion Utilities

    /// <summary>
    /// Convert an algorithm enum to string.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    internal static extern string yh_algorithm_to_string(YhAlgorithm algorithm);

    /// <summary>
    /// Parse an algorithm string to enum.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_string_to_algorithm(
        [MarshalAs(UnmanagedType.LPStr)] string string_algorithm,
        out YhAlgorithm algorithm);

    /// <summary>
    /// Convert an object type enum to string.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    internal static extern string yh_object_type_to_string(YhObjectType objectType);

    /// <summary>
    /// Parse an object type string to enum.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_string_to_object_type(
        [MarshalAs(UnmanagedType.LPStr)] string string_object_type,
        out YhObjectType objectType);

    /// <summary>
    /// Convert capabilities struct to string array.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_capabilities_to_strings(
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] strings,
        uint stringCount);

    /// <summary>
    /// Parse capability strings to struct.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_string_to_capabilities(
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] strings,
        uint stringCount,
        [MarshalAs(UnmanagedType.LPArray, SizeConst = 8)] byte[] capabilities);

    /// <summary>
    /// Convert domain bitmask to string.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_domains_to_string(
        ushort domains,
        StringBuilder outStr,
        nuint maxLen);

    /// <summary>
    /// Parse domain string to bitmask.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_string_to_domains(
        [MarshalAs(UnmanagedType.LPStr)] string string_domains,
        out ushort domains);

    /// <summary>
    /// Convert option enum to string.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    internal static extern string yh_option_to_string(YhOption option);

    /// <summary>
    /// Parse option string to enum.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_string_to_option(
        [MarshalAs(UnmanagedType.LPStr)] string string_option,
        out YhOption option);

    /// <summary>
    /// Get error description string.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.LPStr)]
    internal static extern string yh_strerror(YhReturnCode errorCode);

    #endregion

    #region Logging & Debugging

    /// <summary>
    /// Set library verbosity level.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern void yh_set_verbosity(byte verbosity);

    /// <summary>
    /// Set debug output file.
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_set_debug_output(
        [MarshalAs(UnmanagedType.LPStr)] string filename);

    #endregion

    #region Session Utilities

    /// <summary>
    /// Close a session (alternative to destroy).
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConv, SetLastError = true)]
    internal static extern YhReturnCode yh_util_close_session(IntPtr session);

    #endregion
}
