using System.Data;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace YubiHsmSharp;

/// <summary>
/// Debug levels
/// </summary>
[Flags]
public enum Verbosity
{
    /// <summary>
    /// Debug level quiet. No messages printed out
    /// </summary>
    Quiet = 0x00,

    /// <summary>
    /// Debug level intermediate. Intermediate results printed out
    /// </summary>
    Intermediate = 0x01,

    /// <summary>
    /// Debug level crypto. Crypto results printed out
    /// </summary>
    Crypto = 0x02,

    /// <summary>
    /// Debug level raw. Raw messages printed out
    /// </summary>
    Raw = 0x04,

    /// <summary>
    /// Debug level info. General information messages printed out
    /// </summary>
    Info = 0x08,

    /// <summary>
    /// Debug level error. Error messages printed out
    /// </summary>
    Error = 0x10,

    /// <summary>
    /// Debug level all. All previous options enabled
    /// </summary>
    All = 0xff,
}

/// <summary>
/// Command definitions
/// </summary>
public enum Command
{
    /// <summary>Echo data back from the device.</summary>
    Echo = 0x01,
    EchoResponse = 0x01 | YH_CMD_RESP_FLAG,

    /// <summary>Create a session with the device.</summary>
    CreateSession = 0x03,
    CreateSessionResponse = 0x03 | YH_CMD_RESP_FLAG,

    /// <summary>Authenticate the session to the device</summary>
    AuthenticateSession = 0x04,
    AuthenticateSessionResponse = 0x04 | YH_CMD_RESP_FLAG,

    /// <summary>Send a command over an established session</summary>
    SessionMessage = 0x05,
    SessionMessageResponse = 0x05 | YH_CMD_RESP_FLAG,

    /// <summary>Get device metadata</summary>
    GetDeviceInfo = 0x06,
    GetDeviceInfoResponse = 0x06 | YH_CMD_RESP_FLAG,

    /// <summary>Factory reset a device</summary>
    ResetDevice = 0x08,
    ResetDeviceResponse = 0x08 | YH_CMD_RESP_FLAG,

    /// <summary>Get the device pubkey for asym auth</summary>
    GetDevicePubKey = 0x0a,
    GetDevicePubKeyResponse = 0x0a | YH_CMD_RESP_FLAG,

    /// <summary>Close session</summary>
    CloseSession = 0x40,
    CloseSessionResponse = 0x40 | YH_CMD_RESP_FLAG,

    /// <summary>Get storage information</summary>
    GetStorageInfo = 0x041,
    GetStorageInfoResponse = 0x041 | YH_CMD_RESP_FLAG,

    /// <summary>Import an Opaque Object into the device</summary>
    PutOpaque = 0x42,
    PutOpaqueResponse = 0x42 | YH_CMD_RESP_FLAG,

    /// <summary>Get an Opaque Object from device</summary>
    GetOpaque = 0x43,
    GetOpaqueResponse = 0x43 | YH_CMD_RESP_FLAG,

    /// <summary>Import an Authentication Key into the device</summary>
    PutAuthenticationKey = 0x44,
    PutAuthenticationKeyResponse = 0x44 | YH_CMD_RESP_FLAG,

    /// <summary>Import an Asymmetric Key into the device</summary>
    PutAsymmetricKey = 0x45,
    PutAsymmetricKeyResponse = 0x45 | YH_CMD_RESP_FLAG,

    /// <summary>Generate an Asymmetric Key in the device</summary>
    GenerateAsymmetricKey = 0x46,
    GenerateAsymmetricKeyResponse = 0x46 | YH_CMD_RESP_FLAG,

    /// <summary>Sign data using RSA-PKCS#1v1.5</summary>
    SignPKCS1 = 0x47,
    SignPKCS1Response = 0x47 | YH_CMD_RESP_FLAG,

    /// <summary>List objects in the device</summary>
    ListObjects = 0x48,
    ListObjectsResponse = 0x48 | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt data that was encrypted using RSA-PKCS#1v1.5</summary>
    DecryptPKCS1 = 0x49,
    DecryptPKCS1Response = 0x49 | YH_CMD_RESP_FLAG,

    /// <summary>Get an Object under wrap from the device.</summary>
    ExportWrapped = 0x4a,
    ExportWrappedResponse = 0x4a | YH_CMD_RESP_FLAG,

    /// <summary>Import a wrapped Object into the device</summary>
    ImportWrapped = 0x4b,
    ImportWrappedResponse = 0x4b | YH_CMD_RESP_FLAG,

    /// <summary>Import a Wrap Key into the device</summary>
    PutWrapKey = 0x4c,
    PutWrapKeyResponse = 0x4c | YH_CMD_RESP_FLAG,

    /// <summary>Get all current audit log entries from the device Log Store</summary>
    GetLogEntries = 0x4d,
    GetLogEntriesResponse = 0x4d | YH_CMD_RESP_FLAG,

    /// <summary>Get all metadata about an Object</summary>
    GetObjectInfo = 0x4e,
    GetObjectInfoResponse = 0x4e | YH_CMD_RESP_FLAG,

    /// <summary>Set a device-global options that affect general behavior</summary>
    SetOption = 0x4f,
    SetOptionResponse = 0x4f | YH_CMD_RESP_FLAG,

    /// <summary>Get a device-global option</summary>
    GetOption = 0x50,
    GetOptionResponse = 0x50 | YH_CMD_RESP_FLAG,

    /// <summary>Get a fixed number of pseudo-random bytes from the device</summary>
    GetPseudoRandom = 0x51,
    GetPseudoRandomResponse = 0x51 | YH_CMD_RESP_FLAG,

    /// <summary>Import a HMAC key into the device</summary>
    PutHmacKey = 0x52,
    PutHmacKeyResponse = 0x52 | YH_CMD_RESP_FLAG,

    /// <summary>Perform an HMAC operation in the device</summary>
    SignHmac = 0x53,
    SignHmacResponse = 0x53 | YH_CMD_RESP_FLAG,

    /// <summary>Get the public key of an Asymmetric Key in the device</summary>
    GetPublicKey = 0x54,
    GetPublicKeyResponse = 0x54 | YH_CMD_RESP_FLAG,

    /// <summary>Sign data using RSA-PSS</summary>
    SignPss = 0x55,
    SignPssResponse = 0x55 | YH_CMD_RESP_FLAG,

    /// <summary>Sign data using ECDSA</summary>
    SignEcdsa = 0x56,
    SignEcdsaResponse = 0x56 | YH_CMD_RESP_FLAG,

    /// <summary>Perform an ECDH key exchange operation with a private key in the device</summary>
    DeriveEcdh = 0x57,
    DeriveEcdhResponse = 0x57 | YH_CMD_RESP_FLAG,

    /// <summary>Delete object in the device</summary>
    DeleteObject = 0x58,
    DeleteObjectResponse = 0x58 | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt data using RSA-OAEP</summary>
    DecryptOaep = 0x59,
    DecryptOaepResponse = 0x59 | YH_CMD_RESP_FLAG,

    /// <summary>Generate an HMAC Key in the device</summary>
    GenerateHmacKey = 0x5a,
    GenerateHmacKeyResponse = 0x5a | YH_CMD_RESP_FLAG,

    /// <summary>Generate a Wrap Key in the device</summary>
    GenerateWrapKey = 0x5b,
    GenerateWrapKeyResponse = 0x5b | YH_CMD_RESP_FLAG,

    /// <summary>Verify a generated HMAC</summary>
    VerifyHmac = 0x5c,
    VerifyHmacResponse = 0x5c | YH_CMD_RESP_FLAG,

    /// <summary>Sign SSH certificate request</summary>
    SignSshCertificate = 0x5d,
    SignSshCertificateResponse = 0x5d | YH_CMD_RESP_FLAG,

    /// <summary>Import a template into the device</summary>
    PutTemplate = 0x5e,
    PutTemplateResponse = 0x5e | YH_CMD_RESP_FLAG,

    /// <summary>Get a template from the device</summary>
    GetTemplate = 0x5f,
    GetTemplateResponse = 0x5f | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt a Yubico OTP</summary>
    DecryptOtp = 0x60,
    DecryptOtpResponse = 0x60 | YH_CMD_RESP_FLAG,

    /// <summary>Create a Yubico OTP AEAD</summary>
    CreateOtpAead = 0x61,
    CreateOtpAeadResponse = 0x61 | YH_CMD_RESP_FLAG,

    /// <summary>Generate an OTP AEAD from random data</summary>
    RandomizeOtpAead = 0x62,
    RandomizeOtpAeadResponse = 0x62 | YH_CMD_RESP_FLAG,

    /// <summary>Re-encrypt a Yubico OTP AEAD from one OTP AEAD Key to another OTP AEAD Key</summary>
    RewrapOtpAead = 0x63,
    RewrapOtpAeadResponse = 0x63 | YH_CMD_RESP_FLAG,

    /// <summary>Get attestation of an Asymmetric Key</summary>
    SignAttestationCertificate = 0x64,
    SignAttestationCertificateResponse = 0x64 | YH_CMD_RESP_FLAG,

    /// <summary>Import an OTP AEAD Key into the device</summary>
    PutOtpAeadKey = 0x65,
    PutOtpAeadKeyResponse = 0x65 | YH_CMD_RESP_FLAG,

    /// <summary>Generate an OTP AEAD Key in the device</summary>
    GenerateOtpAeadKey = 0x66,
    GenerateOtpAeadKeyResponse = 0x66 | YH_CMD_RESP_FLAG,

    /// <summary>Set the last extracted audit log entry</summary>
    SetLogIndex = 0x67,
    SetLogIndexResponse = 0x67 | YH_CMD_RESP_FLAG,

    /// <summary>Encrypt (wrap) data using a Wrap Key</summary>
    WrapData = 0x68,
    WrapDataResponse = 0x68 | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt (unwrap) data using a Wrap Key</summary>
    UnwrapData = 0x69,
    UnwrapDataResponse = 0x69 | YH_CMD_RESP_FLAG,

    /// <summary>Sign data using EdDSA</summary>
    SignEdDSA = 0x6a,
    SignEdDSAResponse = 0x6a | YH_CMD_RESP_FLAG,

    /// <summary>Blink the LED of the device</summary>
    BlinkDevice = 0x6b,
    BlinkDeviceResponse = 0x6b | YH_CMD_RESP_FLAG,

    /// <summary>Replace the Authentication Key used to establish the current Session</summary>
    ChangeAuthenticationKey = 0x6c,
    ChangeAuthenticationKeyResponse = 0x6c | YH_CMD_RESP_FLAG,

    /// <summary>Import a Symmetric Key into the device</summary>
    PutSymmetricKey = 0x6d,
    PutSymmetricKeyResponse = 0x6d | YH_CMD_RESP_FLAG,

    /// <summary>Generate a Symmetric Key in the device</summary>
    GenerateSymmetricKey = 0x6e,
    GenerateSymmetricKeyResponse = 0x6e | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt data using a Symmetric Key with ECB</summary>
    DecryptEcb = 0x6f,
    DecryptEcbResponse = 0x6f | YH_CMD_RESP_FLAG,

    /// <summary>Encrypt data using a Symmetric Key with ECB</summary>
    EncryptEcb = 0x70,
    EncryptEcbResponse = 0x70 | YH_CMD_RESP_FLAG,

    /// <summary>Decrypt data using a Symmetric Key with CBC</summary>
    DecryptCbc = 0x71,
    DecryptCbcResponse = 0x71 | YH_CMD_RESP_FLAG,

    /// <summary>Encrypt data using a Symmetric Key with CBC</summary>
    EncryptCbc = 0x72,
    EncryptCbcResponse = 0x72 | YH_CMD_RESP_FLAG,

    /// <summary>Import public RSA key as a Public Wrap Key</summary>
    PutPublicWrapKey = 0x73,
    PutPublicWrapKeyResponse = 0x73 | YH_CMD_RESP_FLAG,

    /// <summary>Export (a)symmetric key using a Public Wrap Key</summary>
    GetRsaWrappedKey = 0x74,
    GetRsaWrappedKeyResponse = 0x74 | YH_CMD_RESP_FLAG,

    /// <summary>Import (a)symmetric key after unwrapping in using and RSA wrap key</summary>
    PutRsaWrappedKey = 0x75,
    PutRsaWrappedKeyResponse = 0x75 | YH_CMD_RESP_FLAG,

    /// <summary>Wrap an object using an RSA Wrap Key</summary>
    ExportRsaWrapped = 0x76,
    ExportRsaWrappedResponse = 0x76 | YH_CMD_RESP_FLAG,

    /// <summary>Import an object after unwrapping in using and RSA Wrap Key</summary>
    ImportRsaWrapped = 0x77,
    ImportRsaWrappedResponse = 0x77 | YH_CMD_RESP_FLAG,

    /// <summary>The response byte returned from the device if the command resulted in an error</summary>
    Error = 0x7f,
}

/// <summary>
/// Algorithms
/// </summary>
/// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithm.html"/>
public enum Algorithm
{
    /// <summary>rsa-pkcs1-sha1</summary>
    RsaPkcs1Sha1 = 1,

    /// <summary>rsa-pkcs1-sha256</summary>
    RsaPkcs1Sha256 = 2,

    /// <summary>rsa-pkcs1-sha384</summary>
    RsaPkcs1Sha384 = 3,

    /// <summary>rsa-pkcs1-sha512</summary>
    RsaPkcs1Sha512 = 4,

    /// <summary>rsa-pss-sha1</summary>
    RsaPssSha1 = 5,

    /// <summary>rsa-pss-sha256</summary>
    RsaPssSha256 = 6,

    /// <summary>rsa-pss-sha384</summary>
    RsaPssSha384 = 7,

    /// <summary>rsa-pss-sha512</summary>
    RsaPssSha512 = 8,

    /// <summary>rsa2048</summary>
    Rsa2048 = 9,

    /// <summary>rsa3072</summary>
    Rsa3072 = 10,

    /// <summary>rsa4096</summary>
    Rsa4096 = 11,

    /// <summary>ecp256</summary>
    Ecp256 = 12,

    /// <summary>ecp384</summary>
    Ecp384 = 13,

    /// <summary>ecp521</summary>
    Ecp521 = 14,

    /// <summary>eck256</summary>
    Eck256 = 15,

    /// <summary>ecbp256</summary>
    Ecbp256 = 16,

    /// <summary>ecbp384</summary>
    Ecbp384 = 17,

    /// <summary>ecbp512</summary>
    Ecbp512 = 18,

    /// <summary>hmac-sha1</summary>
    HmacSha1 = 19,

    /// <summary>hmac-sha256</summary>
    HmacSha256 = 20,

    /// <summary>hmac-sha384</summary>
    HmacSha384 = 21,

    /// <summary>hmac-sha512</summary>
    HmacSha512 = 22,

    /// <summary>ecdsa-sha1</summary>
    EcdsaSha1 = 23,

    /// <summary>ecdh</summary>
    Ecdh = 24,

    /// <summary>rsa-oaep-sha1</summary>
    RsaOaepSha1 = 25,

    /// <summary>rsa-oaep-sha256</summary>
    RsaOaepSha256 = 26,

    /// <summary>rsa-oaep-sha384</summary>
    RsaOaepSha384 = 27,

    /// <summary>rsa-oaep-sha512</summary>
    RsaOaepSha512 = 28,

    /// <summary>aes128-ccm-wrap</summary>
    Aes128CcmWrap = 29,

    /// <summary>opaque-data</summary>
    OpaqueData = 30,

    /// <summary>opaque-x509-certificate</summary>
    OpaqueX509Certificate = 31,

    /// <summary>mgf1-sha1</summary>
    Mgf1Sha1 = 32,

    /// <summary>mgf1-sha256</summary>
    Mgf1Sha256 = 33,

    /// <summary>mgf1-sha384</summary>
    Mgf1Sha384 = 34,

    /// <summary>mgf1-sha512</summary>
    Mgf1Sha512 = 35,

    /// <summary>template-ssh</summary>
    TemplateSsh = 36,

    /// <summary>aes128-yubico-otp</summary>
    Aes128YubicoOtp = 37,

    /// <summary>aes128-yubico-authentication</summary>
    Aes128YubicoAuthentication = 38,

    /// <summary>aes192-yubico-otp</summary>
    Aes192YubicoOtp = 39,

    /// <summary>aes256-yubico-otp</summary>
    Aes256YubicoOtp = 40,

    /// <summary>aes192-ccm-wrap</summary>
    Aes192CcmWrap = 41,

    /// <summary>aes256-ccm-wrap</summary>
    Aes256CcmWrap = 42,

    /// <summary>ecdsa-sha256</summary>
    EcdsaSha256 = 43,

    /// <summary>ecdsa-sha384</summary>
    EcdsaSha384 = 44,

    /// <summary>ecdsa-sha512</summary>
    EcdsaSha512 = 45,

    /// <summary>ed25519</summary>
    Ed25519 = 46,

    /// <summary>ecp224</summary>
    Ecp224 = 47,

    /// <summary>rsa-pkcs1-decrypt</summary>
    RsaPkcs1Decrypt = 48,

    /// <summary>ec-p256-yubico-authentication</summary>
    ECP256YubicoAuthentication = 49,

    /// <summary>aes128</summary>
    Aes128 = 50,

    /// <summary>aes192</summary>
    Aes192 = 51,

    /// <summary>aes256</summary>
    Aes256 = 52,

    /// <summary>aes-ecb</summary>
    AesEcb = 53,

    /// <summary>aes-cbc</summary>
    AesCbc = 54,

    /// <summary>aes-kwp</summary>
    AesKwp = 55,
}

/// <summary>
/// Represents a (pending) connection to a YubiHSM device.
/// </summary>
public sealed class YubiConnector : IDisposable
{
    private static readonly SafeConnectorHandle NullConnectorHandle = new();

    private readonly SafeConnectorHandle handle;

    internal YubiConnector(SafeConnectorHandle handle)
    {
        this.handle = handle;
    }

    /// <summary>
    /// Gets or sets the global verbosity level when executing device commands.
    /// This value may be set before initializing the module.
    /// </summary>
    public static Verbosity Verbosity
    {
        get
        {
            yh_rc err = yh_get_verbosity(out yh_verbosity value);
            YubiHsmException.ThrowIfError(err);
            return (Verbosity)value;
        }
        set
        {
            yh_rc err = yh_set_verbosity(NullConnectorHandle, (yh_verbosity)value);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the verbosity level for this connector instance.
    /// This value overrides the global verbosity for this connector,
    /// but it does not affect other connectors.
    /// </summary>
    /// <param name="verbosity">The verbosity level to set on this connector</param>
    public void SetVerbosity(Verbosity verbosity)
    {
        yh_rc err = yh_set_verbosity(this.handle, (yh_verbosity)verbosity);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Sets the CA certificate file path to validate the connector with. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the CA certificate file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetCertificateAuthority(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_CA, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the proxy server URL to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8ProxyUrl">The proxy server URL, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetProxyServer(ReadOnlySpan<byte> utf8ProxyUrl)
    {
        fixed (byte* pUtf8ProxyUrl = utf8ProxyUrl)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_PROXY_SERVER, pUtf8ProxyUrl);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the client certificate file path to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the client certificate file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetClientCertificate(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_CERT, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the client certificate key file path to use for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8FilePath">File path to the client certificate key file, UTF-8 encoded and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetClientCertificateKey(ReadOnlySpan<byte> utf8FilePath)
    {
        fixed (byte* pUtf8FilePath = utf8FilePath)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_HTTPS_KEY, pUtf8FilePath);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Sets the no-proxy list for this connector. Not implemented on Windows.
    /// </summary>
    /// <param name="utf8NoProxy">The no-proxy list, comma-separated, UTF-8 encoded, and null-terminated</param>
    [UnsupportedOSPlatform("windows")]
    public unsafe void SetNoProxy(ReadOnlySpan<byte> utf8NoProxy)
    {
        fixed (byte* pUtf8NoProxy = utf8NoProxy)
        {
            yh_rc err = yh_set_connector_option(this.handle, yh_connector_option.YH_CONNECTOR_NOPROXY, pUtf8NoProxy);
            YubiHsmException.ThrowIfError(err);
        }
    }

    /// <summary>
    /// Connect to the device through this connector.
    /// </summary>
    /// <param name="timeout">Connection timeout in seconds, 0 for no timeout.</param>
    public void Connect(int timeout = 0)
    {
        yh_rc err = yh_connect(this.handle, timeout);
        YubiHsmException.ThrowIfError(err);
    }

    /// <summary>
    /// Sends a plaintext message to the device through this connector.
    /// </summary>
    /// <param name="request">The command to send.</param>
    /// <param name="requestData">The request data to send.</param>
    /// <param name="responseBuffer">The buffer to receive the response.</param>
    /// <param name="responseLength">The length of the received response.</param>
    /// <returns>The response command.</returns>
    /// <seealso cref="YubiSession.SendMessage"/> 
    public Command SendMessage(Command request, ReadOnlySpan<byte> requestData, Span<byte> responseBuffer, out int responseLength)
    {
        yh_rc err = yh_send_plain_msg(this.handle, (yh_cmd)request, requestData, (nuint)requestData.Length,
            out yh_cmd responseCmd, responseBuffer, out nuint responseLen);
        YubiHsmException.ThrowIfError(err);
        responseLength = (int)responseLen;
        return (Command)responseCmd;
    }

    /// <summary>
    /// Creates a new session using an encryption key and MAC key derived from a password.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="password">The password to derive the keys from</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the password in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> password, bool recreateSession = false)
    {
        yh_rc err = yh_create_session_derived(this.handle, authKeyId, password, (nuint)password.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    /// <summary>
    /// Creates a new session using the provided encryption key and MAC key.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="encryptionKey">The encryption key</param>
    /// <param name="macKey">The MAC key</param>
    /// <param name="recreateSession">If true, the session will be recreated if expired. This caches the keys in memory.</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> macKey, bool recreateSession = false)
    {
        yh_rc err = yh_create_session(this.handle, authKeyId, encryptionKey, (nuint)encryptionKey.Length, macKey, (nuint)macKey.Length, recreateSession, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    /// <summary>
    /// Creates a new session using encryption keys from a platform-specific key store.
    /// </summary>
    /// <param name="authKeyId">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="utf8EncryptionKeyName">The name of the encryption key in the key store, UTF-8 encoded and null-terminated</param>
    /// <param name="utf8MacKeyName">The name of the MAC key in the key store, UTF-8 encoded and null-terminated</param>
    /// <returns>The created session</returns>
    public YubiSession CreateSession(ushort authKeyId, ReadOnlySpan<byte> utf8EncryptionKeyName, ReadOnlySpan<byte> utf8MacKeyName)
    {
        yh_rc err = yh_create_session_ex(this.handle, authKeyId, utf8EncryptionKeyName, utf8MacKeyName, out SafeSessionHandle sessionHandle);
        YubiHsmException.ThrowIfError(err);
        return new YubiSession(sessionHandle);
    }

    // TODO: yh_begin_create_session and yh_finish_create_session for external authentication

    /// <summary>
    /// Gets the value and algorithm of the device public key.
    /// </summary>
    /// <param name="responseBuffer">Buffer to store the public key value</param>
    /// <param name="responseLength">Output parameter for the length of the public key value</param>
    /// <returns>The algorithm of the device public key</returns>
    public Algorithm GetDevicePublicKey(Span<byte> responseBuffer, out int responseLength)
    {
        yh_rc err = yh_util_get_device_pubkey(this.handle, responseBuffer, out nuint responseLen, out yh_algorithm alg);
        YubiHsmException.ThrowIfError(err);
        responseLength = (int)responseLen;
        return (Algorithm)alg;
    }

    /// <summary>
    /// Disconnect from the device and clean up resources associated with this connector.
    /// </summary>
    public void Dispose()
    {
        this.handle.Dispose();
    }
}

internal class SafeConnectorHandle : SafeHandle
{
    public SafeConnectorHandle() : base(IntPtr.Zero, true) { }

    public override bool IsInvalid => this.handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        yh_rc err = yh_disconnect(this.handle);
        return err == yh_rc.YHR_SUCCESS;
    }
}