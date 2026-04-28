namespace YubiHsmSharp;

/// <summary>
/// Libyubihsm is a library for communicating with a YubiHSM 2 device.
/// </summary>
/// <remarks>
/// <para>
/// Usage: <br/>
/// Debug output is controlled with the function <see cref="yh_set_verbosity()"/>
/// </para>
/// <para>
/// First step of using a YubiHSM 2 device is to initialize the library with <see cref="yh_init()"/>,
/// initialize a connector with <see cref="yh_init_connector()"/> and then connect it to the YubiHSM 2
/// with <see cref="yh_connect()"/>. After this, a session must be established with
/// <see cref="yh_create_session_derived()"/> , <see cref="yh_create_session()"/>,
/// <see cref="yh_begin_create_session()"/> + <see cref="yh_finish_create_session()"/>.
/// </para>
/// <para>
/// When a session is established, commands can be exchanged over it. The functions in the namespace
/// yh_util are high-level convenience functions that do specific tasks with the device.
/// </para>
/// </remarks>
/// <example>
/// Here is a small example of establishing a session with a YubiHSM 2 and fetching some
/// pseudo random bytes before closing the session.
/// <code>
/// using System.Diagnostics;
/// using static YubiHsmSharp.yubihsm;
/// 
/// public static void Main() {
///   byte[] data = new byte[128];
///   int dataLen = data.Length;
/// 
///   Debug.Assert(yh_init() == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_init_connector("http://localhost:12345", out SafeConnectorHandle connector) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_connect(connector, 0) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_create_session_derived(connector, 1, YH_DEFAULT_PASSWORD, YH_DEFAULT_PASSWORD.Length,
///     false, out SafeSessionHandle session) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_util_get_pseudo_random(session, dataLen, data, out dataLen) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(dataLen == data.Length);
///   Debug.Assert(yh_util_close_session(session) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_destroy_session(ref session) == yh_rc.YHR_SUCCESS);
///   Debug.Assert(yh_disconnect(connector) == yh_rc.YHR_SUCCESS);
/// }
/// </code>
/// </example>
/// <seealso>yubihsm.h</seealso> 
public static class yubihsm
{
    /// <summary>
    /// Length of context array for authentication
    /// </summary>
    public const int YH_CONTEXT_LEN = 16;

    /// <summary>
    /// Length of host challenge for authentication
    /// </summary>
    public const int YH_HOST_CHAL_LEN = 8;

#if !FUZZING
    public const int YH_MSG_BUF_SIZE = 3136;
#else
    // In fuzzing builds make the data buffers smaller
    public const int YH_MSG_BUF_SIZE = 100;
#endif

    /// <summary>
    /// Length of authentication keys
    /// </summary>
    public const int YH_KEY_LEN = 16;

    /// <summary>
    /// Device vendor ID
    /// </summary>
    public const int YH_VID = 0x1050;

    /// <summary>
    /// Device product ID
    /// </summary>
    public const int YH_PID = 0x0030;

    /// <summary>
    /// Response flag for commands
    /// </summary>
    public const int YH_CMD_RESP_FLAG = 0x80;

    /// <summary>
    /// Max items the device may hold
    /// </summary>
    public const int YH_MAX_ITEMS_COUNT = 256;

    /// <summary>
    /// Max sessions the device may hold.
    /// </summary>
    public const int YH_MAX_SESSIONS = 16;

    /// <summary>
    /// Default encryption key
    /// </summary>
    public static readonly byte[] YH_DEFAULT_ENC_KEY =
        [0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55, 0xe4, 0x20];

    /// <summary>
    /// Default MAC key
    /// </summary>
    public static readonly byte[] YH_DEFAULT_MAC_KEY =
        [0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45, 0x05, 0xd2, 0xce, 0x0a];

    /// <summary>
    /// Default authentication key password
    /// </summary>
    public const string YH_DEFAULT_PASSWORD = "password";

    /// <summary>
    /// Salt to be used for PBKDF2 key derivation
    /// </summary>
    public const string YH_DEFAULT_SALT = "Yubico";

    /// <summary>
    /// Number of iterations for PBKDF2 key derivation
    /// </summary>
    public const int YH_DEFAULT_ITERS = 10000;

    /// <summary>
    /// Length of capabilities array
    /// </summary>
    public const int YH_CAPABILITIES_LEN = 8;

    /// <summary>
    /// Max log entries the device may hold
    /// </summary>
    public const int YH_MAX_LOG_ENTRIES = 64;

    /// <summary>
    /// Max length of object labels
    /// </summary>
    public const int YH_OBJ_LABEL_LEN = 40;

    /// <summary>
    /// Max number of domains
    /// </summary>
    public const int YH_MAX_DOMAINS = 16;

    /// <summary>
    /// Size that the log digest is truncated to
    /// </summary>
    public const int YH_LOG_DIGEST_SIZE = 16;

    /// <summary>
    /// URL scheme used for direct USB access
    /// </summary>
    public const string YH_USB_URL_SCHEME = "yhusb://";

    /// <summary>
    /// URL scheme used for fuzzing builds
    /// </summary>
    public const string YH_FUZZ_URL_SCHEME = "yhfuzz://";

    /// <summary>
    /// Debug levels
    /// </summary>
    [Flags]
    public enum yh_verbosity
    {
        /// <summary>
        /// Debug level quiet. No messages printed out
        /// </summary>
        YH_VERB_QUIET = 0x00,

        /// <summary>
        /// Debug level intermediate. Intermediate results printed out
        /// </summary>
        YH_VERB_INTERMEDIATE = 0x01,

        /// <summary>
        /// Debug level crypto. Crypto results printed out
        /// </summary>
        YH_VERB_CRYPTO = 0x02,

        /// <summary>
        /// Debug level raw. Raw messages printed out
        /// </summary>
        YH_VERB_RAW = 0x04,

        /// <summary>
        /// Debug level info. General information messages printed out
        /// </summary>
        YH_VERB_INFO = 0x08,

        /// <summary>
        /// Debug level error. Error messages printed out
        /// </summary>
        YH_VERB_ERR = 0x10,

        /// <summary>
        /// Debug level all. All previous options enabled
        /// </summary>
        YH_VERB_ALL = 0xff,
    }

    /// <summary>
    /// This is the overhead when doing aes-ccm wrapping: 1 byte identifier,
    /// 13 bytes nonce and 16 bytes mac
    /// </summary>
    public const int YH_CCM_WRAP_OVERHEAD = 1 + 13 + 16;

    public const int YH_EC_P256_PRIVKEY_LEN = 32;
    public const int YH_EC_256_PUBKEY_LEN = 65;

    /// <summary>
    /// Return codes.
    /// </summary>
    public enum yh_rc
    {
        /// <summary>Returned value when function was successful</summary>
        YHR_SUCCESS = 0,

        /// <summary>Returned value when unable to allocate memory</summary>
        YHR_MEMORY_ERROR = -1,

        /// <summary>Returned value when failing to initialize libyubihsm</summary>
        YHR_INIT_ERROR = -2,

        /// <summary>Returned value when a connection error was encountered</summary>
        YHR_CONNECTION_ERROR = -3,

        /// <summary>Returned value when failing to find a suitable connector</summary>
        YHR_CONNECTOR_NOT_FOUND = -4,

        /// <summary>Returned value when an argument to a function is invalid</summary>
        YHR_INVALID_PARAMETERS = -5,

        /// <summary>Returned value when there is a mismatch between expected and received
        /// length of an argument to a function</summary>
        YHR_WRONG_LENGTH = -6,

        /// <summary>Returned value when there is not enough space to store data</summary>
        YHR_BUFFER_TOO_SMALL = -7,

        /// <summary>Returned value when failing to verify cryptogram</summary>
        YHR_CRYPTOGRAM_MISMATCH = -8,

        /// <summary>Returned value when failing to authenticate the session</summary>
        YHR_SESSION_AUTHENTICATION_FAILED = -9,

        /// <summary>Returned value when failing to verify MAC</summary>
        YHR_MAC_MISMATCH = -10,

        /// <summary>Returned value when the device returned no error</summary>
        YHR_DEVICE_OK = -11,

        /// <summary>Returned value when the device receives and invalid command</summary>
        YHR_DEVICE_INVALID_COMMAND = -12,

        /// <summary>Returned value when the device receives a malformed command invalid data</summary>
        YHR_DEVICE_INVALID_DATA = -13,

        /// <summary>Returned value when the device session is invalid</summary>
        YHR_DEVICE_INVALID_SESSION = -14,

        /// <summary>Returned value when the device fails to encrypt or verify the message</summary>
        YHR_DEVICE_AUTHENTICATION_FAILED = -15,

        /// <summary>Returned value when no more sessions can be opened on the device</summary>
        YHR_DEVICE_SESSIONS_FULL = -16,

        /// <summary>Returned value when failing to create a device session</summary>
        YHR_DEVICE_SESSION_FAILED = -17,

        /// <summary>Returned value when encountering a storage failure on the device</summary>
        YHR_DEVICE_STORAGE_FAILED = -18,

        /// <summary>Returned value when there is a mismatch between expected and received
        /// length of an argument to a function on the device</summary>
        YHR_DEVICE_WRONG_LENGTH = -19,

        /// <summary>Returned value when the permissions to perform the operation are wrong</summary>
        YHR_DEVICE_INSUFFICIENT_PERMISSIONS = -20,

        /// <summary>Returned value when the log buffer is full and forced audit is set</summary>
        YHR_DEVICE_LOG_FULL = -21,

        /// <summary>Returned value when the object not found on the device</summary>
        YHR_DEVICE_OBJECT_NOT_FOUND = -22,

        /// <summary>Returned value when an invalid Object ID is used</summary>
        YHR_DEVICE_INVALID_ID = -23,

        /// <summary>Returned value when an invalid OTP is submitted</summary>
        YHR_DEVICE_INVALID_OTP = -24,

        /// <summary>Returned value when the device is in demo mode and has to be power cycled</summary>
        YHR_DEVICE_DEMO_MODE = -25,

        /// <summary>Returned value when the command execution has not terminated</summary>
        YHR_DEVICE_COMMAND_UNEXECUTED = -26,

        /// <summary>Returned value when encountering an unknown error</summary>
        YHR_GENERIC_ERROR = -27,

        /// <summary>Returned value when trying to add an object with an ID that already exists</summary>
        YHR_DEVICE_OBJECT_EXISTS = -28,

        /// <summary>Returned value when connector operation failed</summary>
        YHR_CONNECTOR_ERROR = -29,

        /// <summary>Returned value when encountering SSH CA constraint violation</summary>
        YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION = -30,

        /// <summary>Returned value when an algorithm is disabled</summary>
        YHR_DEVICE_ALGORITHM_DISABLED = -31,
    }

    /// <summary>
    /// Command definitions
    /// </summary>
    public enum yh_cmd
    {
        /// <summary>Echo data back from the device.</summary>
        YHC_ECHO = 0x01,
        YHC_ECHO_R = 0x01 | YH_CMD_RESP_FLAG,

        /// <summary>Create a session with the device.</summary>
        YHC_CREATE_SESSION = 0x03,
        YHC_CREATE_SESSION_R = 0x03 | YH_CMD_RESP_FLAG,

        /// <summary>Authenticate the session to the device</summary>
        YHC_AUTHENTICATE_SESSION = 0x04,
        YHC_AUTHENTICATE_SESSION_R = 0x04 | YH_CMD_RESP_FLAG,

        /// <summary>Send a command over an established session</summary>
        YHC_SESSION_MESSAGE = 0x05,
        YHC_SESSION_MESSAGE_R = 0x05 | YH_CMD_RESP_FLAG,

        /// <summary>Get device metadata</summary>
        YHC_GET_DEVICE_INFO = 0x06,
        YHC_GET_DEVICE_INFO_R = 0x06 | YH_CMD_RESP_FLAG,

        /// <summary>Factory reset a device</summary>
        YHC_RESET_DEVICE = 0x08,
        YHC_RESET_DEVICE_R = 0x08 | YH_CMD_RESP_FLAG,

        /// <summary>Get the device pubkey for asym auth</summary>
        YHC_GET_DEVICE_PUBKEY = 0x0a,
        YHC_GET_DEVICE_PUBKEY_R = 0x0a | YH_CMD_RESP_FLAG,

        /// <summary>Close session</summary>
        YHC_CLOSE_SESSION = 0x40,
        YHC_CLOSE_SESSION_R = 0x40 | YH_CMD_RESP_FLAG,

        /// <summary>Get storage information</summary>
        YHC_GET_STORAGE_INFO = 0x041,
        YHC_GET_STORAGE_INFO_R = 0x041 | YH_CMD_RESP_FLAG,

        /// <summary>Import an Opaque Object into the device</summary>
        YHC_PUT_OPAQUE = 0x42,
        YHC_PUT_OPAQUE_R = 0x42 | YH_CMD_RESP_FLAG,

        /// <summary>Get an Opaque Object from device</summary>
        YHC_GET_OPAQUE = 0x43,
        YHC_GET_OPAQUE_R = 0x43 | YH_CMD_RESP_FLAG,

        /// <summary>Import an Authentication Key into the device</summary>
        YHC_PUT_AUTHENTICATION_KEY = 0x44,
        YHC_PUT_AUTHENTICATION_KEY_R = 0x44 | YH_CMD_RESP_FLAG,

        /// <summary>Import an Asymmetric Key into the device</summary>
        YHC_PUT_ASYMMETRIC_KEY = 0x45,
        YHC_PUT_ASYMMETRIC_KEY_R = 0x45 | YH_CMD_RESP_FLAG,

        /// <summary>Generate an Asymmetric Key in the device</summary>
        YHC_GENERATE_ASYMMETRIC_KEY = 0x46,
        YHC_GENERATE_ASYMMETRIC_KEY_R = 0x46 | YH_CMD_RESP_FLAG,

        /// <summary>Sign data using RSA-PKCS#1v1.5</summary>
        YHC_SIGN_PKCS1 = 0x47,
        YHC_SIGN_PKCS1_R = 0x47 | YH_CMD_RESP_FLAG,

        /// <summary>List objects in the device</summary>
        YHC_LIST_OBJECTS = 0x48,
        YHC_LIST_OBJECTS_R = 0x48 | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt data that was encrypted using RSA-PKCS#1v1.5</summary>
        YHC_DECRYPT_PKCS1 = 0x49,
        YHC_DECRYPT_PKCS1_R = 0x49 | YH_CMD_RESP_FLAG,

        /// <summary>Get an Object under wrap from the device.</summary>
        YHC_EXPORT_WRAPPED = 0x4a,
        YHC_EXPORT_WRAPPED_R = 0x4a | YH_CMD_RESP_FLAG,

        /// <summary>Import a wrapped Object into the device</summary>
        YHC_IMPORT_WRAPPED = 0x4b,
        YHC_IMPORT_WRAPPED_R = 0x4b | YH_CMD_RESP_FLAG,

        /// <summary>Import a Wrap Key into the device</summary>
        YHC_PUT_WRAP_KEY = 0x4c,
        YHC_PUT_WRAP_KEY_R = 0x4c | YH_CMD_RESP_FLAG,

        /// <summary>Get all current audit log entries from the device Log Store</summary>
        YHC_GET_LOG_ENTRIES = 0x4d,
        YHC_GET_LOG_ENTRIES_R = 0x4d | YH_CMD_RESP_FLAG,

        /// <summary>Get all metadata about an Object</summary>
        YHC_GET_OBJECT_INFO = 0x4e,
        YHC_GET_OBJECT_INFO_R = 0x4e | YH_CMD_RESP_FLAG,

        /// <summary>Set a device-global options that affect general behavior</summary>
        YHC_SET_OPTION = 0x4f,
        YHC_SET_OPTION_R = 0x4f | YH_CMD_RESP_FLAG,

        /// <summary>Get a device-global option</summary>
        YHC_GET_OPTION = 0x50,
        YHC_GET_OPTION_R = 0x50 | YH_CMD_RESP_FLAG,

        /// <summary>Get a fixed number of pseudo-random bytes from the device</summary>
        YHC_GET_PSEUDO_RANDOM = 0x51,
        YHC_GET_PSEUDO_RANDOM_R = 0x51 | YH_CMD_RESP_FLAG,

        /// <summary>Import a HMAC key into the device</summary>
        YHC_PUT_HMAC_KEY = 0x52,
        YHC_PUT_HMAC_KEY_R = 0x52 | YH_CMD_RESP_FLAG,

        /// <summary>Perform an HMAC operation in the device</summary>
        YHC_SIGN_HMAC = 0x53,
        YHC_SIGN_HMAC_R = 0x53 | YH_CMD_RESP_FLAG,

        /// <summary>Get the public key of an Asymmetric Key in the device</summary>
        YHC_GET_PUBLIC_KEY = 0x54,
        YHC_GET_PUBLIC_KEY_R = 0x54 | YH_CMD_RESP_FLAG,

        /// <summary>Sign data using RSA-PSS</summary>
        YHC_SIGN_PSS = 0x55,
        YHC_SIGN_PSS_R = 0x55 | YH_CMD_RESP_FLAG,

        /// <summary>Sign data using ECDSA</summary>
        YHC_SIGN_ECDSA = 0x56,
        YHC_SIGN_ECDSA_R = 0x56 | YH_CMD_RESP_FLAG,

        /// <summary>Perform an ECDH key exchange operation with a private key in the device</summary>
        YHC_DERIVE_ECDH = 0x57,
        YHC_DERIVE_ECDH_R = 0x57 | YH_CMD_RESP_FLAG,

        /// <summary>Delete object in the device</summary>
        YHC_DELETE_OBJECT = 0x58,
        YHC_DELETE_OBJECT_R = 0x58 | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt data using RSA-OAEP</summary>
        YHC_DECRYPT_OAEP = 0x59,
        YHC_DECRYPT_OAEP_R = 0x59 | YH_CMD_RESP_FLAG,

        /// <summary>Generate an HMAC Key in the device</summary>
        YHC_GENERATE_HMAC_KEY = 0x5a,
        YHC_GENERATE_HMAC_KEY_R = 0x5a | YH_CMD_RESP_FLAG,

        /// <summary>Generate a Wrap Key in the device</summary>
        YHC_GENERATE_WRAP_KEY = 0x5b,
        YHC_GENERATE_WRAP_KEY_R = 0x5b | YH_CMD_RESP_FLAG,

        /// <summary>Verify a generated HMAC</summary>
        YHC_VERIFY_HMAC = 0x5c,
        YHC_VERIFY_HMAC_R = 0x5c | YH_CMD_RESP_FLAG,

        /// <summary>Sign SSH certificate request</summary>
        YHC_SIGN_SSH_CERTIFICATE = 0x5d,
        YHC_SIGN_SSH_CERTIFICATE_R = 0x5d | YH_CMD_RESP_FLAG,

        /// <summary>Import a template into the device</summary>
        YHC_PUT_TEMPLATE = 0x5e,
        YHC_PUT_TEMPLATE_R = 0x5e | YH_CMD_RESP_FLAG,

        /// <summary>Get a template from the device</summary>
        YHC_GET_TEMPLATE = 0x5f,
        YHC_GET_TEMPLATE_R = 0x5f | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt a Yubico OTP</summary>
        YHC_DECRYPT_OTP = 0x60,
        YHC_DECRYPT_OTP_R = 0x60 | YH_CMD_RESP_FLAG,

        /// <summary>Create a Yubico OTP AEAD</summary>
        YHC_CREATE_OTP_AEAD = 0x61,
        YHC_CREATE_OTP_AEAD_R = 0x61 | YH_CMD_RESP_FLAG,

        /// <summary>Generate an OTP AEAD from random data</summary>
        YHC_RANDOMIZE_OTP_AEAD = 0x62,
        YHC_RANDOMIZE_OTP_AEAD_R = 0x62 | YH_CMD_RESP_FLAG,

        /// <summary>Re-encrypt a Yubico OTP AEAD from one OTP AEAD Key to another OTP AEAD Key</summary>
        YHC_REWRAP_OTP_AEAD = 0x63,
        YHC_REWRAP_OTP_AEAD_R = 0x63 | YH_CMD_RESP_FLAG,

        /// <summary>Get attestation of an Asymmetric Key</summary>
        YHC_SIGN_ATTESTATION_CERTIFICATE = 0x64,
        YHC_SIGN_ATTESTATION_CERTIFICATE_R = 0x64 | YH_CMD_RESP_FLAG,

        /// <summary>Import an OTP AEAD Key into the device</summary>
        YHC_PUT_OTP_AEAD_KEY = 0x65,
        YHC_PUT_OTP_AEAD_KEY_R = 0x65 | YH_CMD_RESP_FLAG,

        /// <summary>Generate an OTP AEAD Key in the device</summary>
        YHC_GENERATE_OTP_AEAD_KEY = 0x66,
        YHC_GENERATE_OTP_AEAD_KEY_R = 0x66 | YH_CMD_RESP_FLAG,

        /// <summary>Set the last extracted audit log entry</summary>
        YHC_SET_LOG_INDEX = 0x67,
        YHC_SET_LOG_INDEX_R = 0x67 | YH_CMD_RESP_FLAG,

        /// <summary>Encrypt (wrap) data using a Wrap Key</summary>
        YHC_WRAP_DATA = 0x68,
        YHC_WRAP_DATA_R = 0x68 | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt (unwrap) data using a Wrap Key</summary>
        YHC_UNWRAP_DATA = 0x69,
        YHC_UNWRAP_DATA_R = 0x69 | YH_CMD_RESP_FLAG,

        /// <summary>Sign data using EdDSA</summary>
        YHC_SIGN_EDDSA = 0x6a,
        YHC_SIGN_EDDSA_R = 0x6a | YH_CMD_RESP_FLAG,

        /// <summary>Blink the LED of the device</summary>
        YHC_BLINK_DEVICE = 0x6b,
        YHC_BLINK_DEVICE_R = 0x6b | YH_CMD_RESP_FLAG,

        /// <summary>Replace the Authentication Key used to establish the current Session</summary>
        YHC_CHANGE_AUTHENTICATION_KEY = 0x6c,
        YHC_CHANGE_AUTHENTICATION_KEY_R = 0x6c | YH_CMD_RESP_FLAG,

        /// <summary>Import a Symmetric Key into the device</summary>
        YHC_PUT_SYMMETRIC_KEY = 0x6d,
        YHC_PUT_SYMMETRIC_KEY_R = 0x6d | YH_CMD_RESP_FLAG,

        /// <summary>Generate a Symmetric Key in the device</summary>
        YHC_GENERATE_SYMMETRIC_KEY = 0x6e,
        YHC_GENERATE_SYMMETRIC_KEY_R = 0x6e | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt data using a Symmetric Key with ECB</summary>
        YHC_DECRYPT_ECB = 0x6f,
        YHC_DECRYPT_ECB_R = 0x6f | YH_CMD_RESP_FLAG,

        /// <summary>Encrypt data using a Symmetric Key with ECB</summary>
        YHC_ENCRYPT_ECB = 0x70,
        YHC_ENCRYPT_ECB_R = 0x70 | YH_CMD_RESP_FLAG,

        /// <summary>Decrypt data using a Symmetric Key with CBC</summary>
        YHC_DECRYPT_CBC = 0x71,
        YHC_DECRYPT_CBC_R = 0x71 | YH_CMD_RESP_FLAG,

        /// <summary>Encrypt data using a Symmetric Key with CBC</summary>
        YHC_ENCRYPT_CBC = 0x72,
        YHC_ENCRYPT_CBC_R = 0x72 | YH_CMD_RESP_FLAG,

        /// <summary>Import public RSA key as a Public Wrap Key</summary>
        YHC_PUT_PUBLIC_WRAPKEY = 0x73,
        YHC_PUT_PUBLIC_WRAPKEY_R = 0x73 | YH_CMD_RESP_FLAG,

        /// <summary>Export (a)symmetric key using a Public Wrap Key</summary>
        YHC_GET_RSA_WRAPPED_KEY = 0x74,
        YHC_GET_RSA_WRAPPED_KEY_R = 0x74 | YH_CMD_RESP_FLAG,

        /// <summary>Import (a)symmetric key after unwrapping in using and RSA wrap key</summary>
        YHC_PUT_RSA_WRAPPED_KEY = 0x75,
        YHC_PUT_RSA_WRAPPED_KEY_R = 0x75 | YH_CMD_RESP_FLAG,

        /// <summary>Wrap an object using an RSA Wrap Key</summary>
        YHC_EXPORT_RSA_WRAPPED = 0x76,
        YHC_EXPORT_RSA_WRAPPED_R = 0x76 | YH_CMD_RESP_FLAG,

        /// <summary>Import an object after unwrapping in using and RSA Wrap Key</summary>
        YHC_IMPORT_RSA_WRAPPED = 0x77,
        YHC_IMPORT_RSA_WRAPPED_R = 0x77 | YH_CMD_RESP_FLAG,

        /// <summary>The response byte returned from the device if the command resulted in an error</summary>
        YHC_ERROR = 0x7f,
    }

    /// <summary>
    /// Object types
    /// </summary>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html"/>
    public enum yh_object_type
    {
        /// <summary>Opaque Object is an unchecked kind of Object, normally used to store
        /// raw data in the device</summary>
        YH_OPAQUE = 0x01,

        /// <summary>Authentication Key is used to establish Sessions with a device</summary>
        YH_AUTHENTICATION_KEY = 0x02,

        /// <summary>Asymmetric Key is the private key of an asymmetric key-pair</summary>
        YH_ASYMMETRIC_KEY = 0x03,

        /// <summary>Wrap Key is a secret key used to wrap and unwrap Objects during the
        /// export and import process</summary>
        YH_WRAP_KEY = 0x04,

        /// <summary>HMAC Key is a secret key used when computing and verifying HMAC signatures</summary>
        YH_HMAC_KEY = 0x05,

        /// <summary>Template is a binary object used for example to validate SSH certificate
        /// requests</summary>
        YH_TEMPLATE = 0x06,

        /// <summary>OTP AEAD Key is a secret key used to decrypt Yubico OTP values</summary>
        YH_OTP_AEAD_KEY = 0x07,

        /// <summary>Symmetric Key is a secret key used for encryption and decryption.</summary>
        YH_SYMMETRIC_KEY = 0x08,

        /// <summary>Public Wrap Key is a public key used to wrap Objects during the
        /// export process</summary>
        YH_PUBLIC_WRAP_KEY = 0x09,

        /// <summary>Public Key is the public key of an asymmetric key-pair. The public key
        /// never exists in device and is mostly here for PKCS#11.</summary>
        YH_PUBLIC_KEY = YH_ASYMMETRIC_KEY | 0x80,

        /// <summary>Wrap Key public is the public key of an asymmetric wrap key. The public key
        /// never exists in device and is mostly here for PKCS#11.</summary>
        YH_WRAP_KEY_PUBLIC = YH_WRAP_KEY | 0x80,
    }
}
