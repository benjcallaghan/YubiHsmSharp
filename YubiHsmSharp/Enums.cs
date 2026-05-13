namespace YubiHsmSharp;

/// <summary>
/// YubiHSM return codes (error codes and status values).
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
public enum YhReturnCode
{
    /// <summary>
    /// Success (YHR_SUCCESS in C library).
    /// </summary>
    Success = 0,

    /// <summary>
    /// Memory allocation error.
    /// </summary>
    MemoryError = -1,

    /// <summary>
    /// Library initialization error.
    /// </summary>
    InitError = -2,

    /// <summary>
    /// Connection error.
    /// </summary>
    ConnectionError = -3,

    /// <summary>
    /// Connector not found.
    /// </summary>
    ConnectorNotFound = -4,

    /// <summary>
    /// Invalid parameters.
    /// </summary>
    InvalidParameters = -5,

    /// <summary>
    /// Wrong data length.
    /// </summary>
    WrongLength = -6,

    /// <summary>
    /// Session not found.
    /// </summary>
    SessionNotFound = -7,

    /// <summary>
    /// Authentication failed.
    /// </summary>
    AuthenticationFailed = -8,

    /// <summary>
    /// Sessions full (16 max concurrent sessions).
    /// </summary>
    SessionsFull = -9,

    /// <summary>
    /// Session setup error.
    /// </summary>
    SessionSetupError = -10,

    /// <summary>
    /// Device storage full.
    /// </summary>
    StorageFull = -11,

    /// <summary>
    /// Insufficient permissions for operation.
    /// </summary>
    InsufficientPermissions = -12,

    /// <summary>
    /// Audit log full.
    /// </summary>
    AuditLogFull = -13,

    /// <summary>
    /// Object not found on device.
    /// </summary>
    ObjectNotFound = -14,

    /// <summary>
    /// Invalid object ID.
    /// </summary>
    InvalidId = -15,

    /// <summary>
    /// Device communication error.
    /// </summary>
    DeviceOk = 0x00,

    /// <summary>
    /// Invalid command sent to device.
    /// </summary>
    DeviceInvalidCommand = 0x01,

    /// <summary>
    /// Invalid data in command.
    /// </summary>
    DeviceInvalidData = 0x02,

    /// <summary>
    /// Invalid or expired session.
    /// </summary>
    DeviceInvalidSession = 0x03,

    /// <summary>
    /// Authentication failed on device.
    /// </summary>
    DeviceAuthenticationFailed = 0x04,

    /// <summary>
    /// No sessions available on device (16 max).
    /// </summary>
    DeviceSessionsFull = 0x05,

    /// <summary>
    /// Session channel setup failed.
    /// </summary>
    DeviceSessionChannelSetupFailed = 0x06,

    /// <summary>
    /// Device storage full.
    /// </summary>
    DeviceStorageFull = 0x07,

    /// <summary>
    /// Wrong data length in command.
    /// </summary>
    DeviceWrongLength = 0x08,

    /// <summary>
    /// Insufficient permissions for operation.
    /// </summary>
    DeviceInsufficientPermissions = 0x09,

    /// <summary>
    /// Audit log full and forced.
    /// </summary>
    DeviceAuditLogFull = 0x0A,

    /// <summary>
    /// Object not found on device.
    /// </summary>
    DeviceObjectNotFound = 0x0B,

    /// <summary>
    /// Invalid object ID.
    /// </summary>
    DeviceInvalidId = 0x0C,

    /// <summary>
    /// Invalid OTP.
    /// </summary>
    DeviceInvalidOtp = 0x0D,

    /// <summary>
    /// Demo mode limitations.
    /// </summary>
    DeviceDemoMode = 0x0E,

    /// <summary>
    /// Command execution failed.
    /// </summary>
    DeviceCommandError = 0x0F,

    /// <summary>
    /// Object already exists.
    /// </summary>
    DeviceObjectExists = 0x10,

    /// <summary>
    /// Device not ready.
    /// </summary>
    DeviceNotReady = 0x11,

    /// <summary>
    /// Generic device error.
    /// </summary>
    DeviceGenericError = 0x12,
}

/// <summary>
/// YubiHSM object types.
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
public enum YhObjectType : byte
{
    /// <summary>
    /// Opaque object (uninterpreted blob).
    /// </summary>
    Opaque = 0x01,

    /// <summary>
    /// Authentication key (used for session establishment).
    /// </summary>
    AuthenticationKey = 0x02,

    /// <summary>
    /// HMAC key (used for HMAC operations).
    /// </summary>
    HmacKey = 0x03,

    /// <summary>
    /// Binary key (generic symmetric key).
    /// </summary>
    BinaryKey = 0x04,

    /// <summary>
    /// RSA private key.
    /// </summary>
    RsaPrivateKey = 0x05,

    /// <summary>
    /// RSA public key.
    /// </summary>
    RsaPublicKey = 0x06,

    /// <summary>
    /// EC private key.
    /// </summary>
    EcPrivateKey = 0x07,

    /// <summary>
    /// EC public key.
    /// </summary>
    EcPublicKey = 0x08,

    /// <summary>
    /// OTP AEAD key.
    /// </summary>
    OtpAeadKey = 0x09,
}

/// <summary>
/// YubiHSM cryptographic algorithms.
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
public enum YhAlgorithm : byte
{
    // HMAC algorithms
    /// <summary>
    /// HMAC-SHA1.
    /// </summary>
    HmacSha1 = 0x01,

    /// <summary>
    /// HMAC-SHA256.
    /// </summary>
    HmacSha256 = 0x02,

    /// <summary>
    /// HMAC-SHA384.
    /// </summary>
    HmacSha384 = 0x03,

    /// <summary>
    /// HMAC-SHA512.
    /// </summary>
    HmacSha512 = 0x04,

    // RSA algorithms
    /// <summary>
    /// RSA 2048-bit.
    /// </summary>
    Rsa2048 = 0x05,

    /// <summary>
    /// RSA 3072-bit.
    /// </summary>
    Rsa3072 = 0x06,

    /// <summary>
    /// RSA 4096-bit.
    /// </summary>
    Rsa4096 = 0x07,

    // EC algorithms
    /// <summary>
    /// EC P-256 (secp256r1).
    /// </summary>
    EcP256 = 0x08,

    /// <summary>
    /// EC P-384 (secp384r1).
    /// </summary>
    EcP384 = 0x09,

    /// <summary>
    /// EC P-521 (secp521r1).
    /// </summary>
    EcP521 = 0x0A,

    /// <summary>
    /// EC secp256k1 (Bitcoin/Ethereum curve).
    /// </summary>
    EcSecp256k1 = 0x0B,

    /// <summary>
    /// EC Brainpool P-256.
    /// </summary>
    EcBpP256 = 0x0C,

    /// <summary>
    /// EC Brainpool P-384.
    /// </summary>
    EcBpP384 = 0x0D,

    /// <summary>
    /// EC Brainpool P-512.
    /// </summary>
    EcBpP512 = 0x0E,

    /// <summary>
    /// Ed25519 (EdDSA).
    /// </summary>
    Ed25519 = 0x0F,

    // AES algorithms
    /// <summary>
    /// AES-128.
    /// </summary>
    Aes128 = 0x10,

    /// <summary>
    /// AES-192.
    /// </summary>
    Aes192 = 0x11,

    /// <summary>
    /// AES-256.
    /// </summary>
    Aes256 = 0x12,

    // Wrapping algorithms
    /// <summary>
    /// AES-CCM for wrapping.
    /// </summary>
    AesCcmWrap = 0x13,

    // Additional EC algorithms
    /// <summary>
    /// EC Ed448 (EdDSA).
    /// </summary>
    Ed448 = 0x14,

    /// <summary>
    /// HMAC-SHA224.
    /// </summary>
    HmacSha224 = 0x15,

    /// <summary>
    /// AES-XTS-128.
    /// </summary>
    AesXts128 = 0x16,

    /// <summary>
    /// AES-XTS-256.
    /// </summary>
    AesXts256 = 0x17,

    /// <summary>
    /// EC X25519 (Elliptic Curve Diffie-Hellman).
    /// </summary>
    EcX25519 = 0x18,

    /// <summary>
    /// EC X448 (Elliptic Curve Diffie-Hellman).
    /// </summary>
    EcX448 = 0x19,
}

/// <summary>
/// YubiHSM device commands (low-level operation codes).
/// </summary>
public enum YhCommand : byte
{
    /// <summary>
    /// Echo command (test connectivity).
    /// </summary>
    Echo = 0x01,

    /// <summary>
    /// Create session command.
    /// </summary>
    CreateSession = 0x03,

    /// <summary>
    /// Authenticate session command.
    /// </summary>
    AuthenticateSession = 0x04,

    /// <summary>
    /// Session message command.
    /// </summary>
    SessionMessage = 0x05,

    /// <summary>
    /// Get device info command.
    /// </summary>
    GetDeviceInfo = 0x06,

    /// <summary>
    /// BSL (bootloader) command.
    /// </summary>
    Bsl = 0x07,

    /// <summary>
    /// Reset device command.
    /// </summary>
    ResetDevice = 0x08,

    /// <summary>
    /// Close session command.
    /// </summary>
    CloseSession = 0x40,

    /// <summary>
    /// Get storage info command.
    /// </summary>
    GetStorageInfo = 0x41,

    /// <summary>
    /// Put object command.
    /// </summary>
    PutObject = 0x42,

    /// <summary>
    /// Get object command.
    /// </summary>
    GetObject = 0x43,

    /// <summary>
    /// Put authentication key command.
    /// </summary>
    PutAuthenticationKey = 0x44,

    /// <summary>
    /// Put asymmetric key command.
    /// </summary>
    PutAsymmetricKey = 0x45,

    /// <summary>
    /// Generate asymmetric key command.
    /// </summary>
    GenerateAsymmetricKey = 0x46,

    /// <summary>
    /// Sign data (PKCS) command.
    /// </summary>
    SignPkcs = 0x47,

    /// <summary>
    /// Put symmetric key command.
    /// </summary>
    PutSymmetricKey = 0x48,

    /// <summary>
    /// HMAC key generation command.
    /// </summary>
    GenerateHmacKey = 0x49,

    /// <summary>
    /// HMAC sign command.
    /// </summary>
    HmacData = 0x4A,

    /// <summary>
    /// Get public key command.
    /// </summary>
    GetPublicKey = 0x4B,

    /// <summary>
    /// Sign PSS command.
    /// </summary>
    SignPss = 0x4C,

    /// <summary>
    /// Sign ECDSA command.
    /// </summary>
    SignEcdsa = 0x4D,

    /// <summary>
    /// ECDH command.
    /// </summary>
    EcdhDerivation = 0x4E,

    /// <summary>
    /// Delete object command.
    /// </summary>
    DeleteObject = 0x4F,

    /// <summary>
    /// Decrypt OAEP command.
    /// </summary>
    DecryptOaep = 0x50,

    /// <summary>
    /// Generate symmetric key command.
    /// </summary>
    GenerateSymmetricKey = 0x51,

    /// <summary>
    /// Encrypt data command.
    /// </summary>
    EncryptData = 0x52,

    /// <summary>
    /// Decrypt data command.
    /// </summary>
    DecryptData = 0x53,

    /// <summary>
    /// Reboot command.
    /// </summary>
    Reboot = 0x54,

    /// <summary>
    /// Get object list command.
    /// </summary>
    ListObjects = 0x55,

    /// <summary>
    /// Get object info command.
    /// </summary>
    GetObjectInfo = 0x56,

    /// <summary>
    /// Set option command.
    /// </summary>
    SetOption = 0x57,

    /// <summary>
    /// Get option command.
    /// </summary>
    GetOption = 0x58,

    /// <summary>
    /// Get audit log command.
    /// </summary>
    GetAuditLog = 0x59,

    /// <summary>
    /// Set log index command.
    /// </summary>
    SetLogIndex = 0x5A,

    /// <summary>
    /// Get wrapped command.
    /// </summary>
    GetWrapped = 0x5B,

    /// <summary>
    /// Put wrapped command.
    /// </summary>
    PutWrapped = 0x5C,

    /// <summary>
    /// Get random command.
    /// </summary>
    GetRandom = 0x5D,

    /// <summary>
    /// Generate HMAC key command.
    /// </summary>
    PutHmacKey = 0x5E,

    /// <summary>
    /// Sign EdDSA command.
    /// </summary>
    SignEddsa = 0x5F,

    /// <summary>
    /// Close attestation command.
    /// </summary>
    CloseAttestation = 0x60,

    /// <summary>
    /// Verify attestation command.
    /// </summary>
    VerifyAttestation = 0x61,
}

/// <summary>
/// YubiHSM device options.
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
public enum YhOption : byte
{
    /// <summary>
    /// Force Audit Log (option 0x01).
    /// </summary>
    ForceAuditLog = 0x01,

    /// <summary>
    /// FIPS mode (option 0x02).
    /// </summary>
    FipsMode = 0x02,

    /// <summary>
    /// Reset after authentication failed (option 0x03).
    /// </summary>
    ResetAfterAuthenticationFailed = 0x03,

    /// <summary>
    /// User authentication soft lock (option 0x04).
    /// </summary>
    UserAuthenticationSoftLock = 0x04,
}

/// <summary>
/// YubiHSM connector options.
/// </summary>
public enum YhConnectorOption : byte
{
    /// <summary>
    /// Proxy setup.
    /// </summary>
    Proxy = 0x01,

    /// <summary>
    /// HTTP proxy.
    /// </summary>
    HttpProxy = 0x02,

    /// <summary>
    /// Proxy username.
    /// </summary>
    ProxyUsername = 0x03,

    /// <summary>
    /// Proxy password.
    /// </summary>
    ProxyPassword = 0x04,

    /// <summary>
    /// Certificate file.
    /// </summary>
    CertificateFile = 0x05,

    /// <summary>
    /// Privkey file.
    /// </summary>
    PrivkeyFile = 0x06,

    /// <summary>
    /// CA certificate.
    /// </summary>
    CaCertificate = 0x07,

    /// <summary>
    /// CRL file.
    /// </summary>
    CrlFile = 0x08,

    /// <summary>
    /// Verify host.
    /// </summary>
    VerifyHost = 0x09,

    /// <summary>
    /// Verify peer.
    /// </summary>
    VerifyPeer = 0x0A,
}

/// <summary>
/// YubiHSM capability bits (permissions for objects and authentication keys).
/// See: https://docs.yubico.com/hardware/yubihsm-2/
/// </summary>
[Flags]
public enum YhCapability : ulong
{
    /// <summary>
    /// No capabilities.
    /// </summary>
    None = 0,

    /// <summary>
    /// Sign HMAC data.
    /// </summary>
    SignHmac = 0x01,

    /// <summary>
    /// Verify HMAC signature.
    /// </summary>
    VerifyHmac = 0x02,

    /// <summary>
    /// Sign PKCS#1 v1.5 data.
    /// </summary>
    SignPkcs = 0x04,

    /// <summary>
    /// Sign PSS padded data.
    /// </summary>
    SignPss = 0x08,

    /// <summary>
    /// Sign with ECDSA.
    /// </summary>
    SignEcdsa = 0x10,

    /// <summary>
    /// Sign with EdDSA.
    /// </summary>
    SignEddsa = 0x20,

    /// <summary>
    /// Decrypt OAEP padded data.
    /// </summary>
    DecryptOaep = 0x40,

    /// <summary>
    /// Decrypt PKCS#1 v1.5 padded data.
    /// </summary>
    DecryptPkcs = 0x80,

    /// <summary>
    /// Derive ECDH shared secret.
    /// </summary>
    EcdhDerivation = 0x100,

    /// <summary>
    /// Export wrapped object.
    /// </summary>
    ExportWrapped = 0x200,

    /// <summary>
    /// Import wrapped object.
    /// </summary>
    ImportWrapped = 0x400,

    /// <summary>
    /// Put/replace authentication key.
    /// </summary>
    PutAuthenticationKey = 0x800,

    /// <summary>
    /// Put/replace asymmetric key.
    /// </summary>
    PutAsymmetricKey = 0x1000,

    /// <summary>
    /// Generate asymmetric key.
    /// </summary>
    GenerateAsymmetricKey = 0x2000,

    /// <summary>
    /// Put/replace symmetric key.
    /// </summary>
    PutSymmetricKey = 0x4000,

    /// <summary>
    /// Generate symmetric key.
    /// </summary>
    GenerateSymmetricKey = 0x8000,

    /// <summary>
    /// Put/replace HMAC key.
    /// </summary>
    PutHmacKey = 0x10000,

    /// <summary>
    /// Generate HMAC key.
    /// </summary>
    GenerateHmacKey = 0x20000,

    /// <summary>
    /// Get object (export).
    /// </summary>
    GetObject = 0x40000,

    /// <summary>
    /// Get object metadata (info).
    /// </summary>
    GetObjectInfo = 0x80000,

    /// <summary>
    /// List objects.
    /// </summary>
    ListObjects = 0x100000,

    /// <summary>
    /// Delete object.
    /// </summary>
    DeleteObject = 0x200000,

    /// <summary>
    /// Get option values.
    /// </summary>
    GetOption = 0x400000,

    /// <summary>
    /// Set option values.
    /// </summary>
    SetOption = 0x800000,

    /// <summary>
    /// Get pseudo-random data.
    /// </summary>
    GetPseudoRandom = 0x1000000,

    /// <summary>
    /// Get audit log.
    /// </summary>
    GetAuditLog = 0x2000000,

    /// <summary>
    /// Close session.
    /// </summary>
    CloseSession = 0x4000000,

    /// <summary>
    /// Get session info (attestation, etc).
    /// </summary>
    GetSessionInfo = 0x8000000,

    /// <summary>
    /// Reset device.
    /// </summary>
    ResetDevice = 0x10000000,

    /// <summary>
    /// Force audit log flush.
    /// </summary>
    ForceAuditLog = 0x20000000,

    /// <summary>
    /// Get wrapped/export.
    /// </summary>
    GetWrapped = 0x40000000,

    /// <summary>
    /// Put wrapped/import.
    /// </summary>
    PutWrapped = 0x80000000,

    /// <summary>
    /// Wrap with another key.
    /// </summary>
    WrapWithKey = 0x100000000,

    /// <summary>
    /// Put/replace opaque object.
    /// </summary>
    PutOpaque = 0x200000000,

    /// <summary>
    /// Generate opaque object.
    /// </summary>
    GenerateOpaque = 0x400000000,

    /// <summary>
    /// Get OTP AEAD key.
    /// </summary>
    GetOtpAeadKey = 0x800000000,

    /// <summary>
    /// Generate OTP AEAD key.
    /// </summary>
    GenerateOtpAeadKey = 0x1000000000,

    /// <summary>
    /// Decrypt AES.
    /// </summary>
    DecryptAes = 0x2000000000,

    /// <summary>
    /// Encrypt AES.
    /// </summary>
    EncryptAes = 0x4000000000,

    /// <summary>
    /// Create backup.
    /// </summary>
    CreateBackup = 0x8000000000,

    /// <summary>
    /// Restore backup.
    /// </summary>
    RestoreBackup = 0x10000000000,

    /// <summary>
    /// Verify log.
    /// </summary>
    VerifyLog = 0x20000000000,

    /// <summary>
    /// All capabilities.
    /// </summary>
    All = ulong.MaxValue,
}
