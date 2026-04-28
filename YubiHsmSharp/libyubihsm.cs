using System.Runtime.InteropServices;

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
internal static unsafe partial class libyubihsm
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

    /// Reference to a connector
    // typedef struct yh_connector yh_connector;
    // Opaque struct replaced with SafeConnectorHandle

    /// Reference to a session
    // typedef struct yh_session yh_session;
    // Opaque struct replaced with SafeSessionHandle

    /// <summary>
    /// Capabilities representation
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct yh_capabilities
    {
        /// <summary>
        /// Capabilities is represented as an 8 byte byte array.
        /// </summary>
        fixed byte capabilities[YH_CAPABILITIES_LEN];
    }

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

    /// <summary>
    /// Max number of algorithms defined here
    /// </summary>
    public const int YH_MAX_ALGORITHM_COUNT = 0xff;

    /// <summary>
    /// Algorithms
    /// </summary>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithm.html"/>
    public enum yh_algorithm
    {
        /// <summary>rsa-pkcs1-sha1</summary>
        YH_ALGO_RSA_PKCS1_SHA1 = 1,

        /// <summary>rsa-pkcs1-sha256</summary>
        YH_ALGO_RSA_PKCS1_SHA256 = 2,

        /// <summary>rsa-pkcs1-sha384</summary>
        YH_ALGO_RSA_PKCS1_SHA384 = 3,

        /// <summary>rsa-pkcs1-sha512</summary>
        YH_ALGO_RSA_PKCS1_SHA512 = 4,

        /// <summary>rsa-pss-sha1</summary>
        YH_ALGO_RSA_PSS_SHA1 = 5,

        /// <summary>rsa-pss-sha256</summary>
        YH_ALGO_RSA_PSS_SHA256 = 6,

        /// <summary>rsa-pss-sha384</summary>
        YH_ALGO_RSA_PSS_SHA384 = 7,

        /// <summary>rsa-pss-sha512</summary>
        YH_ALGO_RSA_PSS_SHA512 = 8,

        /// <summary>rsa2048</summary>
        YH_ALGO_RSA_2048 = 9,

        /// <summary>rsa3072</summary>
        YH_ALGO_RSA_3072 = 10,

        /// <summary>rsa4096</summary>
        YH_ALGO_RSA_4096 = 11,

        /// <summary>ecp256</summary>
        YH_ALGO_EC_P256 = 12,

        /// <summary>ecp384</summary>
        YH_ALGO_EC_P384 = 13,

        /// <summary>ecp521</summary>
        YH_ALGO_EC_P521 = 14,

        /// <summary>eck256</summary>
        YH_ALGO_EC_K256 = 15,

        /// <summary>ecbp256</summary>
        YH_ALGO_EC_BP256 = 16,

        /// <summary>ecbp384</summary>
        YH_ALGO_EC_BP384 = 17,

        /// <summary>ecbp512</summary>
        YH_ALGO_EC_BP512 = 18,

        /// <summary>hmac-sha1</summary>
        YH_ALGO_HMAC_SHA1 = 19,

        /// <summary>hmac-sha256</summary>
        YH_ALGO_HMAC_SHA256 = 20,

        /// <summary>hmac-sha384</summary>
        YH_ALGO_HMAC_SHA384 = 21,

        /// <summary>hmac-sha512</summary>
        YH_ALGO_HMAC_SHA512 = 22,

        /// <summary>ecdsa-sha1</summary>
        YH_ALGO_EC_ECDSA_SHA1 = 23,

        /// <summary>ecdh</summary>
        YH_ALGO_EC_ECDH = 24,

        /// <summary>rsa-oaep-sha1</summary>
        YH_ALGO_RSA_OAEP_SHA1 = 25,

        /// <summary>rsa-oaep-sha256</summary>
        YH_ALGO_RSA_OAEP_SHA256 = 26,

        /// <summary>rsa-oaep-sha384</summary>
        YH_ALGO_RSA_OAEP_SHA384 = 27,

        /// <summary>rsa-oaep-sha512</summary>
        YH_ALGO_RSA_OAEP_SHA512 = 28,

        /// <summary>aes128-ccm-wrap</summary>
        YH_ALGO_AES128_CCM_WRAP = 29,

        /// <summary>opaque-data</summary>
        YH_ALGO_OPAQUE_DATA = 30,

        /// <summary>opaque-x509-certificate</summary>
        YH_ALGO_OPAQUE_X509_CERTIFICATE = 31,

        /// <summary>mgf1-sha1</summary>
        YH_ALGO_MGF1_SHA1 = 32,

        /// <summary>mgf1-sha256</summary>
        YH_ALGO_MGF1_SHA256 = 33,

        /// <summary>mgf1-sha384</summary>
        YH_ALGO_MGF1_SHA384 = 34,

        /// <summary>mgf1-sha512</summary>
        YH_ALGO_MGF1_SHA512 = 35,

        /// <summary>template-ssh</summary>
        YH_ALGO_TEMPLATE_SSH = 36,

        /// <summary>aes128-yubico-otp</summary>
        YH_ALGO_AES128_YUBICO_OTP = 37,

        /// <summary>aes128-yubico-authentication</summary>
        YH_ALGO_AES128_YUBICO_AUTHENTICATION = 38,

        /// <summary>aes192-yubico-otp</summary>
        YH_ALGO_AES192_YUBICO_OTP = 39,

        /// <summary>aes256-yubico-otp</summary>
        YH_ALGO_AES256_YUBICO_OTP = 40,

        /// <summary>aes192-ccm-wrap</summary>
        YH_ALGO_AES192_CCM_WRAP = 41,

        /// <summary>aes256-ccm-wrap</summary>
        YH_ALGO_AES256_CCM_WRAP = 42,

        /// <summary>ecdsa-sha256</summary>
        YH_ALGO_EC_ECDSA_SHA256 = 43,

        /// <summary>ecdsa-sha384</summary>
        YH_ALGO_EC_ECDSA_SHA384 = 44,

        /// <summary>ecdsa-sha512</summary>
        YH_ALGO_EC_ECDSA_SHA512 = 45,

        /// <summary>ed25519</summary>
        YH_ALGO_EC_ED25519 = 46,

        /// <summary>ecp224</summary>
        YH_ALGO_EC_P224 = 47,

        /// <summary>rsa-pkcs1-decrypt</summary>
        YH_ALGO_RSA_PKCS1_DECRYPT = 48,

        /// <summary>ec-p256-yubico-authentication</summary>
        YH_ALGO_EC_P256_YUBICO_AUTHENTICATION = 49,

        /// <summary>aes128</summary>
        YH_ALGO_AES128 = 50,

        /// <summary>aes192</summary>
        YH_ALGO_AES192 = 51,

        /// <summary>aes256</summary>
        YH_ALGO_AES256 = 52,

        /// <summary>aes-ecb</summary>
        YH_ALGO_AES_ECB = 53,

        /// <summary>aes-cbc</summary>
        YH_ALGO_AES_CBC = 54,

        /// <summary>aes-kwp</summary>
        YH_ALGO_AES_KWP = 55,
    }

    /// <summary>
    /// Global options
    /// </summary>
    public enum yh_option
    {
        /// <summary>Enable/Disable Forced Audit mode</summary>
        YH_OPTION_FORCE_AUDIT = 1,

        /// <summary>Enable/Disable logging of specific commands</summary>
        YH_OPTION_COMMAND_AUDIT = 3,

        /// <summary>Toggle algorithms on/off</summary>
        YH_OPTION_ALGORITHM_TOGGLE = 4,

        /// <summary>Fips mode on/off</summary>
        YH_OPTION_FIPS_MODE = 5,
    }

    /// <summary>
    /// Options for the connector, set with <see cref="yh_set_connector_option()"/>
    /// </summary>
    public enum yh_connector_option
    {
        /// <summary>File with CA certificate to validate the connector with (const char *).</summary>
        /// <remarks>Not implemented on Windows</remarks>
        YH_CONNECTOR_HTTPS_CA = 1,

        /// <summary>Proxy server to use for connecting to the connector (const char *).</summary>
        /// <remarks>Not implemented on Windows</remarks>
        YH_CONNECTOR_PROXY_SERVER = 2,

        /// <summary>File with client certificate to authenticate client with (const char *).</summary>
        /// <remarks>Not implemented on Windows</remarks>
        YH_CONNECTOR_HTTPS_CERT = 3,

        /// <summary>File with client certificates key (const char *).</summary>
        /// <remarks>Not implemented on Windows</remarks>
        YH_CONNECTOR_HTTPS_KEY = 4,

        /// <summary>Comma separated list of hosts ignoring proxy, `*` to disable proxy.</summary>
        /// <remarks>Not implemented on Windows</remarks>
        YH_CONNECTOR_NOPROXY = 5,
    }

    /// <summary>
    /// Options for data compression
    /// </summary>
    public enum yh_compress_option
    {
        /// <summary>Do not compress data before importing it</summary>
        NO_COMPRESS = 1,

        /// <summary>Compress data if it's too big</summary>
        COMPRESS_IF_TOO_BIG = 2,

        /// <summary>Compress data before importing it</summary>
        COMPRESS = 3,
    }

    /// <summary>
    /// Device info struct
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct yh_device_info
    {
        /// <summary>
        /// Fimrware version major
        /// </summary>
        byte major;

        /// <summary>
        /// Firmware version minor
        /// </summary>
        byte minor;

        /// <summary>
        /// Firmware version patch
        /// </summary>
        byte patch;

        /// <summary>
        /// Device serial number
        /// </summary>
        uint serial;

        /// <summary>
        /// Total available logs
        /// </summary>
        byte log_total;

        /// <summary>
        /// Total used logs
        /// </summary>
        byte log_used;

        /// <summary>
        /// List of algorithms supported by the device
        /// </summary>
        fixed int algorithms[YH_MAX_ALGORITHM_COUNT];

        /// <summary>
        /// Number of algorithms supported by the device
        /// </summary>
        nuint n_algorithms;
    }

    /// <summary>
    /// Logging struct as returned by device
    /// </summary>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Logs.html"/> 
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct yh_log_entry
    {
        /// <summary>
        /// Monotonically increasing index
        /// </summary>
        ushort number;

        /// <summary>
        /// What command was executed
        /// </summary>
        /// <seealso cref="yh_cmd"/> 
        byte command;

        /// <summary>
        /// Length of in-data
        /// </summary>
        ushort length;

        /// <summary>
        /// ID of Authentication Key used
        /// </summary>
        ushort session_key;

        /// <summary>
        /// ID of first Object used
        /// </summary>
        ushort target_key;

        /// <summary>
        /// ID of second Object used
        /// </summary>
        ushort second_key;

        /// <summary>
        /// Command result
        /// </summary>
        /// <seealso cref="yh_cmd"/> 
        byte result;

        /// <summary>
        /// Systick at time of execution
        /// </summary>
        uint systick;

        /// <summary>
        /// Truncated sha256 digest of this last digest + this entry
        /// </summary>
        fixed byte digest[YH_LOG_DIGEST_SIZE];
    }

    /// <summary>
    /// Object descriptor
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct yh_object_descriptor
    {
        /// <summary>
        /// Object capabilities
        /// </summary>
        /// <seealso cref="yh_capabilities"/> 
        yh_capabilities capabilities;

        /// <summary>
        /// Object ID
        /// </summary>
        ushort id;

        /// <summary>
        /// Object length
        /// </summary>
        ushort len;

        /// <summary>
        /// Object domains
        /// </summary>
        ushort domains;

        /// <summary>
        /// Object type
        /// </summary>
        yh_object_type type;

        /// <summary>
        /// Object algorithm
        /// </summary>
        yh_algorithm algorithm;

        /// <summary>
        /// Object sequence
        /// </summary>
        byte sequence;

        /// <summary>
        /// Object origin
        /// </summary>
        byte origin;

        /// <summary>
        /// Object label. The label consists of raw bytes and is not restricted to
        /// printable characters or valid UTF-8 glyphs.
        /// </summary>
        fixed byte label[YH_OBJ_LABEL_LEN + 1];

        /// <summary>
        /// Object delegated capabilities.
        /// </summary>
        yh_capabilities delegated_capabilities;
    }

    private static readonly (string name, int bit)[] yh_capability = [
        ("change-authentication-key", 0x2e),
        ("create-otp-aead", 0x1e),
        ("decrypt-cbc", 0x34),
        ("decrypt-ecb", 0x32),
        ("decrypt-oaep", 0x0a),
        ("decrypt-otp", 0x1d),
        ("decrypt-pkcs", 0x09),
        ("delete-asymmetric-key", 0x29),
        ("delete-authentication-key", 0x28),
        ("delete-hmac-key", 0x2b),
        ("delete-opaque", 0x27),
        ("delete-otp-aead-key", 0x2d),
        ("delete-public-wrap-key", 0x37),
        ("delete-symmetric-key", 0x31),
        ("delete-template", 0x2c),
        ("delete-wrap-key", 0x2a),
        ("derive-ecdh", 0x0b),
        ("encrypt-cbc", 0x35),
        ("encrypt-ecb", 0x33),
        ("export-wrapped", 0x0c),
        ("exportable-under-wrap", 0x10),
        ("generate-asymmetric-key", 0x04),
        ("generate-hmac-key", 0x15),
        ("generate-otp-aead-key", 0x24),
        ("generate-symmetric-key", 0x30),
        ("generate-wrap-key", 0x0f),
        ("get-log-entries", 0x18),
        ("get-opaque", 0x00),
        ("get-option", 0x12),
        ("get-pseudo-random", 0x13),
        ("get-template", 0x1a),
        ("import-wrapped", 0x0d),
        ("put-asymmetric-key", 0x03),
        ("put-authentication-key", 0x02),
        ("put-mac-key", 0x14),
        ("put-opaque", 0x01),
        ("put-otp-aead-key", 0x23),
        ("put-public-wrap-key", 0x36),
        ("put-symmetric-key", 0x2f),
        ("put-template", 0x1b),
        ("put-wrap-key", 0x0e),
        ("randomize-otp-aead", 0x1f),
        ("reset-device", 0x1c),
        ("rewrap-from-otp-aead-key", 0x20),
        ("rewrap-to-otp-aead-key", 0x21),
        ("set-option", 0x11),
        ("sign-attestation-certificate", 0x22),
        ("sign-ecdsa", 0x07),
        ("sign-eddsa", 0x08),
        ("sign-hmac", 0x16),
        ("sign-pkcs", 0x05),
        ("sign-pss", 0x06),
        ("sign-ssh-certificate", 0x19),
        ("unwrap-data", 0x26),
        ("verify-hmac", 0x17),
        ("wrap-data", 0x25),
    ];

    private static readonly (string name, yh_algorithm algorithm)[] yh_algorithms = [
        ("aes128", yh_algorithm.YH_ALGO_AES128),
        ("aes192", yh_algorithm.YH_ALGO_AES192),
        ("aes256", yh_algorithm.YH_ALGO_AES256),
        ("aes128-ccm-wrap", yh_algorithm.YH_ALGO_AES128_CCM_WRAP),
        ("aes128-yubico-authentication", yh_algorithm.YH_ALGO_AES128_YUBICO_AUTHENTICATION),
        ("aes128-yubico-otp", yh_algorithm.YH_ALGO_AES128_YUBICO_OTP),
        ("aes192-ccm-wrap", yh_algorithm.YH_ALGO_AES192_CCM_WRAP),
        ("aes192-yubico-otp", yh_algorithm.YH_ALGO_AES192_YUBICO_OTP),
        ("aes256-ccm-wrap", yh_algorithm.YH_ALGO_AES256_CCM_WRAP),
        ("aes256-yubico-otp", yh_algorithm.YH_ALGO_AES256_YUBICO_OTP),
        ("aes-cbc", yh_algorithm.YH_ALGO_AES_CBC),
        ("aes-ecb", yh_algorithm.YH_ALGO_AES_ECB),
        ("aes-kwp", yh_algorithm.YH_ALGO_AES_KWP),
        ("ecbp256", yh_algorithm.YH_ALGO_EC_BP256),
        ("ecbp384", yh_algorithm.YH_ALGO_EC_BP384),
        ("ecbp512", yh_algorithm.YH_ALGO_EC_BP512),
        ("ecdh", yh_algorithm.YH_ALGO_EC_ECDH),
        ("ecdsa-sha1", yh_algorithm.YH_ALGO_EC_ECDSA_SHA1),
        ("ecdsa-sha256", yh_algorithm.YH_ALGO_EC_ECDSA_SHA256),
        ("ecdsa-sha384", yh_algorithm.YH_ALGO_EC_ECDSA_SHA384),
        ("ecdsa-sha512", yh_algorithm.YH_ALGO_EC_ECDSA_SHA512),
        ("eck256", yh_algorithm.YH_ALGO_EC_K256),
        ("ecp224", yh_algorithm.YH_ALGO_EC_P224),
        ("ecp256", yh_algorithm.YH_ALGO_EC_P256),
        ("ecp256-yubico-authentication", yh_algorithm.YH_ALGO_EC_P256_YUBICO_AUTHENTICATION),
        ("ecp384", yh_algorithm.YH_ALGO_EC_P384),
        ("ecp521", yh_algorithm.YH_ALGO_EC_P521),
        ("ed25519", yh_algorithm.YH_ALGO_EC_ED25519),
        ("hmac-sha1", yh_algorithm.YH_ALGO_HMAC_SHA1),
        ("hmac-sha256", yh_algorithm.YH_ALGO_HMAC_SHA256),
        ("hmac-sha384", yh_algorithm.YH_ALGO_HMAC_SHA384),
        ("hmac-sha512", yh_algorithm.YH_ALGO_HMAC_SHA512),
        ("mgf1-sha1", yh_algorithm.YH_ALGO_MGF1_SHA1),
        ("mgf1-sha256", yh_algorithm.YH_ALGO_MGF1_SHA256),
        ("mgf1-sha384", yh_algorithm.YH_ALGO_MGF1_SHA384),
        ("mgf1-sha512", yh_algorithm.YH_ALGO_MGF1_SHA512),
        ("opaque-data", yh_algorithm.YH_ALGO_OPAQUE_DATA),
        ("opaque-x509-certificate", yh_algorithm.YH_ALGO_OPAQUE_X509_CERTIFICATE),
        ("rsa-oaep-sha1", yh_algorithm.YH_ALGO_RSA_OAEP_SHA1),
        ("rsa-oaep-sha256", yh_algorithm.YH_ALGO_RSA_OAEP_SHA256),
        ("rsa-oaep-sha384", yh_algorithm.YH_ALGO_RSA_OAEP_SHA384),
        ("rsa-oaep-sha512", yh_algorithm.YH_ALGO_RSA_OAEP_SHA512),
        ("rsa-pkcs1-decrypt", yh_algorithm.YH_ALGO_RSA_PKCS1_DECRYPT),
        ("rsa-pkcs1-sha1", yh_algorithm.YH_ALGO_RSA_PKCS1_SHA1),
        ("rsa-pkcs1-sha256", yh_algorithm.YH_ALGO_RSA_PKCS1_SHA256),
        ("rsa-pkcs1-sha384", yh_algorithm.YH_ALGO_RSA_PKCS1_SHA384),
        ("rsa-pkcs1-sha512", yh_algorithm.YH_ALGO_RSA_PKCS1_SHA512),
        ("rsa-pss-sha1", yh_algorithm.YH_ALGO_RSA_PSS_SHA1),
        ("rsa-pss-sha256", yh_algorithm.YH_ALGO_RSA_PSS_SHA256),
        ("rsa-pss-sha384", yh_algorithm.YH_ALGO_RSA_PSS_SHA384),
        ("rsa-pss-sha512", yh_algorithm.YH_ALGO_RSA_PSS_SHA512),
        ("rsa2048", yh_algorithm.YH_ALGO_RSA_2048),
        ("rsa3072", yh_algorithm.YH_ALGO_RSA_3072),
        ("rsa4096", yh_algorithm.YH_ALGO_RSA_4096),
        ("template-ssh", yh_algorithm.YH_ALGO_TEMPLATE_SSH),
    ];

    private static readonly (string name, yh_object_type type)[] yh_types = [
        ("authentication-key", yh_object_type.YH_AUTHENTICATION_KEY),
        ("asymmetric-key", yh_object_type.YH_ASYMMETRIC_KEY),
        ("hmac-key", yh_object_type.YH_HMAC_KEY),
        ("opaque", yh_object_type.YH_OPAQUE),
        ("otp-aead-key", yh_object_type.YH_OTP_AEAD_KEY),
        ("public-wrap-key", yh_object_type.YH_PUBLIC_WRAP_KEY),
        ("symmetric-key", yh_object_type.YH_SYMMETRIC_KEY),
        ("template", yh_object_type.YH_TEMPLATE),
        ("wrap-key", yh_object_type.YH_WRAP_KEY),
    ];

    private static readonly (string name, yh_option option)[] yh_options = [
        ("command-audit", yh_option.YH_OPTION_COMMAND_AUDIT),
        ("force-audit", yh_option.YH_OPTION_FORCE_AUDIT),
        ("algorithm-toggle", yh_option.YH_OPTION_ALGORITHM_TOGGLE),
        ("fips-mode", yh_option.YH_OPTION_FIPS_MODE),
    ];

    /// <summary>
    /// The object was generated on the device
    /// </summary>
    public const int YH_ORIGIN_GENERATED = 0x01;

    /// <summary>
    /// The object was imported into the device
    /// </summary>
    public const int YH_ORIGIN_IMPORTED = 0x02;

    /// <summary>
    /// The object was imported into the device under wrap.
    /// This is used in combination with objects original 'origin'.
    /// </summary>
    public const int YH_ORIGIN_IMPORTED_WRAPPED = 0x10;

    /// <summary>
    /// Return a string describing an error condition
    /// </summary>
    /// <param name="err"><see cref="yh_rc"/> error code</param>
    /// <returns>String with descriptive error</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial byte* yh_strerror(yh_rc err);

    /// <summary>
    /// Set verbosity level when executing commands.
    /// Default verbosity is <see cref="yh_verbosity.YH_VERB_QUIET"/>
    /// </summary>
    /// <remarks>
    /// This function may be called prior to global library initialization to set the debug level
    /// </remarks>
    /// <param name="connector">If not NULL, the verbosity of the specific connector will be set</param>
    /// <param name="verbosity">The desired level of debug output</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/></returns>
    /// <seealso cref="yh_verbosity"/> 
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_set_verbosity(SafeConnectorHandle connector, yh_verbosity verbosity);

    /// <summary>
    /// Get verbosity level when executing commands
    /// </summary>
    /// <param name="verbosity">The verbosity level</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if seccessful [sic].
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if verbosity is NULL</returns>
    /// <seealso cref="yh_verbosity"/> 
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_get_verbosity(out yh_verbosity verbosity);

    /// <summary>
    /// Set file for debug output
    /// </summary>
    /// <param name="connector">If not NULL, the debug messages will be written to the specified output file</param>
    /// <param name="output">The destination of the debug messages</param>
    [LibraryImport(nameof(libyubihsm))]
    // TODO: Add a stronger handle-like type for FILE *output.
    public static partial void yh_set_debug_output(SafeConnectorHandle connector, nint output);

    /// <summary>
    /// Global library initialization
    /// </summary>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/></returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_init();

    /// <summary>
    /// Global library cleanup
    /// </summary>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/></returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_exit();

    /// <summary>
    /// Instantiate a new connector
    /// </summary>
    /// <param name="url">URL associated with this connector</param>
    /// <param name="connector">Connector to the device</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if either the URL or the connector are NULL.
    /// <see cref="yh_rc.YHR_GENERIC_ERROR"/> if failed to load the backend.
    /// <see cref="yh_rc.YHR_MEMORY_ERROR"/> if failed to allocate memory for the connector.
    /// <see cref="yh_rc.YHR_CONNECTION_ERROR"/> if failed to create the connector
    /// </returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_init_connector(ReadOnlySpan<byte> url, out SafeConnectorHandle connector);

    /// <summary>
    /// Set connector options.
    /// Note that backend options are not supported with winhttp or USB connectors
    /// </summary>
    /// <param name="connector">Connector to set an option on</param>
    /// <param name="opt">Option to set. <see cref="yh_connector_option"/></param>
    /// <param name="val">Value of the option. Type of value is specific to the given option</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector or the value are NULL, or if the option is unknown.
    /// <see cref="yh_rc.YHR_CONNECTION_ERROR"/> if failed to set the option.
    /// </returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_set_connector_option(SafeConnectorHandle connector, yh_connector_option opt, void* val);

    /// <summary>
    /// Connect to the device through the specified connector
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="timeout">Connection timeout in seconds</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector does not exist.
    /// </returns>
    /// <seealso cref="yh_rc"/> 
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_connect(SafeConnectorHandle connector, int timeout);

    /// <summary>
    /// Disconnect from a connector
    /// </summary>
    /// <param name="connector">Connector from which to disconnect</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector is NULL
    /// </returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_disconnect(SafeConnectorHandle connector);

    /// <summary>
    /// Send a plain (unencrypted) message to the device through a connector
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="cmd">Command to send <see cref="yh_cmd"/></param>
    /// <param name="data">Data to send</param>
    /// <param name="data_len">length of data to send</param>
    /// <param name="response_cmd">Response command</param>
    /// <param name="response">Response data</param>
    /// <param name="response_len">Length of response data</param>
    /// <returns></returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_send_plain_msg(SafeConnectorHandle connector,
        yh_cmd cmd, ReadOnlySpan<byte> data, nuint data_len,
        out yh_cmd response_cmd, Span<byte> response, out nuint response_len);

    /// <summary>
    /// Send an encrypted message to the device over a session.
    /// The session has to be authenticated.
    /// </summary>
    /// <param name="session">Session to send the message over</param>
    /// <param name="cmd">Command to send</param>
    /// <param name="data">Data to send</param>
    /// <param name="data_len">Length of data to send</param>
    /// <param name="response_cmd">Response command</param>
    /// <param name="response">Response data</param>
    /// <param name="response_len">Length of response data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful.</returns>
    /// <seealso cref="yh_rc"/> 
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_send_secure_msg(SafeSessionHandle session,
        yh_cmd cmd, ReadOnlySpan<byte> data, nuint data_len,
        out yh_cmd response_cmd, Span<byte> response, out nuint response_len);
}
