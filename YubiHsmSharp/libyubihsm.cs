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

    /// <summary>
    /// Create a session that uses an encryption key and a MAC key derived from a password
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="authkey_id">Object ID of the Authentication Key used to authentication the session</param>
    /// <param name="password">Password used to derive the session encryption key and MAC key</param>
    /// <param name="password_len">Length of the password in bytes</param>
    /// <param name="recreate_session">If true, the session will be recreated if expired. This caches the password in memory</param>
    /// <param name="session">The created session</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector, the password or the session are NULL.
    /// <see cref="yh_rc.YHR_GENERIC_ERROR"/> if failed to derive the session encryption key and/or the MAC key or if PRNG related errors occur.
    /// <see cref="yh_rc.YHR_MEMORY_ERROR"/> if failed to allocate memory for the session.
    /// </returns>
    /// <seealso cref="yh_rc"/> 
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_create_session_derived(SafeConnectorHandle connector, ushort authkey_id,
        ReadOnlySpan<byte> password, nuint password_len,
        [MarshalAs(UnmanagedType.U1)] bool recreate_session, out SafeSessionHandle session);

    /// <summary>
    /// Create a session that uses the specified encryption key and MAC key to derive session-specific keys
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="authkey_id">Object ID of the Authentication Key used to authenticate the session</param>
    /// <param name="key_enc">Key used to derive the session encryption key</param>
    /// <param name="key_enc_len">Length of the encryption key</param>
    /// <param name="key_mac">Key used to derive the session MAC key</param>
    /// <param name="key_mac_len">Length of the MAC key</param>
    /// <param name="recreate_session">If true, the session will be recreated if expired. This caches the password in memory</param>
    /// <param name="session">created session</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL or incorrect.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication Key</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_create_session(SafeConnectorHandle connector, ushort authkey_id,
        ReadOnlySpan<byte> key_enc, nuint key_enc_len,
        ReadOnlySpan<byte> key_mac, nuint key_mac_len,
        [MarshalAs(UnmanagedType.U1)] bool recreate_session, out SafeSessionHandle session);

    /// <summary>
    /// Create a session that uses named encryption keys from a platform-specific key store to derive session-specific keys
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="authkey_id">Object ID of the Authentication Key used to authenticate the session</param>
    /// <param name="key_enc_name">Name of key used to derive the session encryption key</param>
    /// <param name="key_mac_name">Name of key used to derive the session MAC keys</param>
    /// <param name="session">created session</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL or incorrect.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication Key</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_create_session_ex(SafeConnectorHandle connector, ushort authkey_id,
        ReadOnlySpan<byte> key_enc_name, ReadOnlySpan<byte> key_mac_name,
        out SafeSessionHandle session);

    /// <summary>
    /// Begin creating a session where the session keys are calculated outside the library.
    /// </summary>
    /// <remarks>
    /// This function must be followed by <see cref="yh_finish_create_session"/> to set the session keys.
    /// If <paramref name="host_challenge_len"/> is 0 when calling this function an 8 byte random challenge is generated,
    /// and symmetric authentication is assumed.
    /// For asymmetric authentication the host challenge must be provided.
    /// <param name="connector">Connector to the device</param>
    /// <param name="authkey_id">Object ID of the Authentication Key used to authenticate the session</param>
    /// <param name="context">pointer to where context data is saved</param>
    /// <param name="host_challenge">Host challenge</param>
    /// <param name="host_challenge_len">Length of the host challenge</param>
    /// <param name="card_cryptogram">Card cryptogram from the device</param>
    /// <param name="card_cryptogram_len">Length of card cryptogram</param>
    /// <param name="session">created session</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// <see cref="yh_rc.YHR_MEMORY_ERROR"/> if failed to allocate memory for the session.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_begin_create_session(SafeConnectorHandle connector, ushort authkey_id,
        out byte* context, Span<byte> host_challenge, out nuint host_challenge_len,
        Span<byte> card_cryptogram, out nuint card_cryptogram_len, out SafeSessionHandle session);

    /// <summary>
    /// Finish creating a session.
    /// </summary>
    /// <remarks>
    /// This function must be called after <see cref="yh_begin_create_session"/>.
    /// For symmetric authentication this function will authenticate the session with the device
    /// using the provided session keys and card cryptogram.
    /// For asymmetric authentication the card cryptogram must be validated externally.
    /// </remarks>
    /// <param name="session">The session created with <see cref="yh_begin_create_session"/></param>
    /// <param name="key_senc">Session encryption key used to encrypt the messages exchanged with the device</param>
    /// <param name="key_senc_len">Lenght [sic] of the encryption key. Must be <see cref="YH_KEY_LEN"/></param>
    /// <param name="key_smac">Session MAC key used for creating the authentication tag for each message</param>
    /// <param name="key_smac_len">Length of the MAC key. Must be <see cref="YH_KEY_LEN"/></param>
    /// <param name="key_srmac">Session return MAC key used for creating the authentication tag for each response message</param>
    /// <param name="key_srmac_len">Length of the return MAC key. Must be <see cref="YH_KEY_LEN"/></param>
    /// <param name="card_cryptogram">Card cryptogram</param>
    /// <param name="card_cryptogram_len">Length of card cryptogram</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL or any of the key lengths are not <see cref="YH_KEY_LEN"/>.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_finish_create_session(SafeSessionHandle session,
        ReadOnlySpan<byte> key_senc, nuint key_senc_len, ReadOnlySpan<byte> key_smac, nuint key_smac_len,
        ReadOnlySpan<byte> key_srmac, nuint key_srmac_len, Span<byte> card_cryptogram, nuint card_cryptogram_len);

    /// <summary>
    /// Utility function that gets the value and algorithm of the device public key
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="device_pubkey">Value of the public key</param>
    /// <param name="device_pubkey_len">Length of the public key in bytes</param>
    /// <param name="algorithm">Algorithm of the key</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if the actual key length was bigger than <paramref name="device_pubkey_len"/>.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_device_pubkey(SafeConnectorHandle connector,
        Span<byte> device_pubkey, out nuint device_pubkey_len, out yh_algorithm algorithm);

    /// <summary>
    /// Utility function that derives an ec-p256 key pair from a password using the following algoirthm.
    /// </summary>
    /// <remarks>
    /// 1. Apply pkcs5_pbkdf2_hmac-sha256 on the password to derive a pseudo-random private ec-p256 key
    /// 2. Check that the derived key is a valid ec-p256 private key
    /// 3. If not valid append a byte with the value 1 (2, 3, 4 etc for additional failures) to the password and go to step 1
    /// 4. Calculate the corresponding public key from the private key and the ec-p256 curve parameters
    /// </remarks>
    /// <param name="password">The password bytes</param>
    /// <param name="password_len">The password length</param>
    /// <param name="privkey">Value of the private key</param>
    /// <param name="privkey_len">Length of the private key in bytes</param>
    /// <param name="pubkey">Value of the public key</param>
    /// <param name="pubkey_len">Length of the public key in bytes</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_derive_ec_p256_key(ReadOnlySpan<byte> password, nuint password_len,
        Span<byte> privkey, nuint privkey_len, Span<byte> pubkey, nuint pubkey_len);

    /// <summary>
    /// Utility function that generates a random ec-p256 key pair
    /// </summary>
    /// <param name="privkey">Value of the private key</param>
    /// <param name="privkey_len">Length of the private key in bytes</param>
    /// <param name="pubkey">Value of the public key</param>
    /// <param name="pubkey_len">Length of the public key in bytes</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_ec_p256_key(Span<byte> privkey, nuint privkey_len,
        Span<byte> pubkey, nuint pubkey_len);

    /// <summary>
    /// Create a session that uses the specified asymmetric key to derive session-specific keys.
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="authkey_id">Object ID of the Asymmetric Authentication Key used to authenticate the session</param>
    /// <param name="privkey">Private key of the client, used to derive the session encryption key and authenticate the client</param>
    /// <param name="privkey_len">Length of the private key</param>
    /// <param name="device_pubkey">Public key of the device, used to derrive the session encryption key and authenticate the device</param>
    /// <param name="device_pubkey_len">Length of the device public key</param>
    /// <param name="session">created session</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL or incorrect.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication Key</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_create_session_asym(SafeConnectorHandle connector, ushort authkey_id,
        ReadOnlySpan<byte> privkey, nuint privkey_len,
        ReadOnlySpan<byte> device_pubkey, nuint device_pubkey_len,
        out SafeSessionHandle session);

    /// <summary>
    /// Free data associated with the session
    /// </summary>
    /// <param name="session">Pointer to the session to destroy</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the session is NULL.
    /// </returns>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_destroy_session(ref SafeSessionHandle session);

    /// <summary>
    /// Deprecated - use yh_begin_create_session instead
    /// </summary>
    [LibraryImport(nameof(libyubihsm))]
    [Obsolete("Use yh_begin_create_session instead")]
    public static partial yh_rc yh_begin_create_session_ext(SafeConnectorHandle connector, ushort authkey_id,
        out byte* context, Span<byte> card_cryptogram, nuint card_cryptogram_len, out SafeSessionHandle session);

    /// <summary>
    /// Deprecated - use yh_finish_create_session instead
    /// </summary>
    [LibraryImport(nameof(libyubihsm))]
    [Obsolete("Use yh_finish_create_session instead")]
    public static partial yh_rc yh_finish_create_session_ext(SafeConnectorHandle connector,
        SafeSessionHandle session, ReadOnlySpan<byte> key_senc, nuint key_senc_len,
        ReadOnlySpan<byte> key_smac, nuint key_smac_len, ReadOnlySpan<byte> key_srmac, nuint key_srmac_len,
        Span<byte> card_cryptogram, nuint card_cryptogram_len);

    /// <summary>
    /// Deprecated, calling this function has no effect.
    /// </summary>
    [LibraryImport(nameof(libyubihsm))]
    [Obsolete("Calling this function has no effect.")]
    public static partial yh_rc yh_authenticate_session(SafeSessionHandle session);

    /// <summary>
    /// Get device info in a struct
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="device_info">Device info</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector or the device_info are NULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if n_algorithms is smaller than the number of actually supported algorithms.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_device_info_ex(SafeConnectorHandle connector,
        out yh_device_info device_info);

    /// <summary>
    /// Get device version, device serial number, supported algorithms and available log entries
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="major">Device major version number</param>
    /// <param name="minor">Device minor version number</param>
    /// <param name="patch">Device build version number</param>
    /// <param name="serial">Device serial number</param>
    /// <param name="log_total">Total number of log entries</param>
    /// <param name="log_used">Number of written log entries</param>
    /// <param name="algorithms">List of supported algorithms</param>
    /// <param name="n_algorithms">Number of supported algorithms</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector isNULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if <paramref name="n_algorithms"/> is smaller than the number of actually supported algorithms.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_device_info(SafeConnectorHandle connector,
        out byte major, out byte minor, out byte patch, out uint serial,
        out byte log_total, out byte log_used,
        Span<yh_algorithm> algorithms, out nuint n_algorithms);

    /// <summary>
    /// Get device version, part number (chip designator) as required by FIPS
    /// </summary>
    /// <param name="connector">Connector to the device</param>
    /// <param name="part_number">Part number (chip designator)</param>
    /// <param name="part_number_len">Size of part_number</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful or of [sic] <paramref name="part_number"/> is NULL
    /// <see cref="yh_rc.YHR_DEVICE_INVALID_COMMAND"/> if firmware version does not support the command
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the connector is NULL.
    /// <see cref="yh_rc.YHR_DEVICE_INVALID_DATA"/> If returned <paramref name="part_number"/> is less than 12 bytes
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if <paramref name="part_number"/> is smaller than 13 bytes
    /// </returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_partnumber(SafeConnectorHandle connector,
        Span<byte> part_number, out nuint part_number_len);

    /// <summary>
    /// List objects accessible from the session
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="id">Object ID to filter by (0 to not filter by ID)</param>
    /// <param name="type">Object type to filter by (0 to not filter by type). <see cref="yh_object_type"/></param>
    /// <param name="domains">Domains to filter by (0 to not filter by domain)</param>
    /// <param name="capabilities">Capabilities to filter by (0 to not filter by capabilities). <see cref="yh_capabilities"/></param>
    /// <param name="algorithm">Algorithm to filter by (0 to not filter by algorithm)</param>
    /// <param name="label">Label to filter by</param>
    /// <param name="objects">Array of objects returned</param>
    /// <param name="n_objects">Max number of objects (will be set to number found on return)</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if <paramref name="n_objects"/> is smaller than the number of objects found.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capabilities</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</seealso>
    /// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Label.html">Labels</seealso>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_list_objects(SafeSessionHandle session, ushort id,
        yh_object_type type, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> label,
        Span<yh_object_descriptor> objects, out nuint n_objects);

    /// <summary>
    /// Get metadata of the object with the specified Object ID and Type
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="id">Object ID of the object to get</param>
    /// <param name="type">Object type. <see cref="yh_object_type"/></param>
    /// <param name="object">Object information</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the session is NULL.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_object_info(SafeSessionHandle session, ushort id,
        yh_object_type type, out yh_object_descriptor @object);

    /// <summary>
    /// Get the value of the public key with the specified Object ID
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="id">Object ID of the public key</param>
    /// <param name="data">Value of the public key</param>
    /// <param name="data_len">Length of the public key in bytes</param>
    /// <param name="algorithm">Algorithm of the key</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if the actual key length was bigger than <paramref name="data_len"/>.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_public_key(SafeSessionHandle session, ushort id,
        Span<byte> data, out nuint data_len, out yh_algorithm algorithm);

    /// <summary>
    /// Get the value of the public key with the specified Object ID and type
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="type">Object type of the public key</param>
    /// <param name="id">Object ID of the public key</param>
    /// <param name="data">Value of the public key</param>
    /// <param name="data_len">Length of the public key in bytes</param>
    /// <param name="algorithm">Algorithm of the key</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL.
    /// <see cref="yh_rc.YHR_BUFFER_TOO_SMALL"/> if the actual key length was bigger than <paramref name="data_len"/>.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_public_key_ex(SafeSessionHandle session, yh_object_type type,
        ushort id, Span<byte> data, out nuint data_len, out yh_algorithm algorithm);

    /// <summary>
    /// Close a session
    /// </summary>
    /// <param name="session">Session to close</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if the session is NULL.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_close_session(SafeSessionHandle session);

    /// <summary>
    /// Sign data using RSA-PKCS#1v1.5
    /// </summary>
    /// <remarks>
    /// <paramref name="in"/> is either a raw hashed message (sha1, sha256, sha384 or sha512)
    /// or that with correct digestinfo pre-pended
    /// </remarks>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the signing key</param>
    /// <param name="hashed">true if data is only hashed</param>
    /// <param name="in">data to sign</param>
    /// <param name="in_len">length of data to sign</param>
    /// <param name="out">signed data</param>
    /// <param name="out_len">length of signed data</param>
    /// <returns>
    /// <see cref="yh_rc.YHR_SUCCESS"/> if successful.
    /// <see cref="yh_rc.YHR_INVALID_PARAMETERS"/> if input parameters are NULL or if <paramref name="in_len"/> is not 20, 32, 48, or 64.
    /// </returns>
    /// <seealso cref="yh_rc"/>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_pkcs1v1_5(SafeSessionHandle session, ushort key_id,
        [MarshalAs(UnmanagedType.U1)] bool hashed, ReadOnlySpan<byte> @in, nuint in_len,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Sign data using RSA-PSS
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the signing key</param>
    /// <param name="in">Data to sign</param>
    /// <param name="in_len">Length of data to sign</param>
    /// <param name="out">Signed data</param>
    /// <param name="out_len">Length of signed data</param>
    /// <param name="salt_len">Length of salt</param>
    /// <param name="mgf1Algo">Algorithm for mgf1</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_pss(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len,
        nuint salt_len, yh_algorithm mgf1Algo);

    /// <summary>
    /// Sign data using ECDSA
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the signing key</param>
    /// <param name="in">Data to sign</param>
    /// <param name="in_len">Length of data to sign</param>
    /// <param name="out">Signed data</param>
    /// <param name="out_len">Length of signed data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_ecdsa(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Sign data using EdDSA
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the signing key</param>
    /// <param name="in">Data to sign</param>
    /// <param name="in_len">Length of data to sign</param>
    /// <param name="out">Signed data</param>
    /// <param name="out_len">Length of signed data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_eddsa(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Sign data using HMAC
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the signing key</param>
    /// <param name="in">Data to HMAC</param>
    /// <param name="in_len">Length of data to hmac</param>
    /// <param name="out">HMAC</param>
    /// <param name="out_len">Length of HMAC</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_hmac(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Get a fixed number of pseudo-random bytes from the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="len">Length of pseudo-random data to get</param>
    /// <param name="out">Pseudo-random data out</param>
    /// <param name="out_len">Length of pseudo-random data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_pseudo_random(SafeSessionHandle session, nuint len,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import an AES key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID the key. 0 if Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm of the key to import</param>
    /// <param name="key">The key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_aes_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> key);

    /// <summary>
    /// Import an RSA key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID the key. 0 if Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm of the key to import</param>
    /// <param name="p">P component of the RSA key to import</param>
    /// <param name="q">Q component of the RSA key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_rsa_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q);

    /// <summary>
    /// Import an Elliptic Curve key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm of the key to import</param>
    /// <param name="s">the EC key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_ec_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> s);

    /// <summary>
    /// Import an ED key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm of the key to import</param>
    /// <param name="k">the ED key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_ed_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> k);

    /// <summary>
    /// Import an HMAC key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm of the key to import</param>
    /// <param name="key">The HMAC key to import</param>
    /// <param name="key_len">Length of the HMAC key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_hmac_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> key, nuint key_len);

    /// <summary>
    /// Generate an AES key in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm to use to generate the AES key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_aes_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm);

    /// <summary>
    /// Generate an RSA key in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm to use to generate the RSA key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_rsa_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm);

    /// <summary>
    /// Generate an Elliptic Curve key in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm to use to generate the EC key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_ec_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm);

    /// <summary>
    /// Generate an ED key in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label for the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the ED key</param>
    /// <param name="algorithm">Algorithm to use to generate the ED key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_ed_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm);

    /// <summary>
    /// Verify a generated HMAC
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the HMAC key</param>
    /// <param name="signature">HMAC signature (20, 32, 48 or 64 bytes)</param>
    /// <param name="signature_len">length of HMAC signature</param>
    /// <param name="data">data to verify</param>
    /// <param name="data_len">length of data to verify</param>
    /// <param name="verified">true if verification succeeded</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_verify_hmac(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> signature, nuint signature_len,
        ReadOnlySpan<byte> data, nuint data_len, [MarshalAs(UnmanagedType.U1)] out bool verified);

    /// <summary>
    /// Generate an HMAC key in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="algorithm">Algorithm to use to generate the HMAC key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_hmac_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm);

    /// <summary>
    /// Decrypt data that was encrypted using RSA-PKCS#1v1.5
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the RSA key to use for decryption</param>
    /// <param name="in">Encrypted data</param>
    /// <param name="in_len">Length of encrypted data</param>
    /// <param name="out">Decrypted data</param>
    /// <param name="out_len">Length of decrypted data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_decrypt_pkcs1v1_5(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Decrypt data using RSA-OAEP
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the RSA key to use for decryption</param>
    /// <param name="in">Encrypted data</param>
    /// <param name="in_len">Length of encrypted data</param>
    /// <param name="out">Decrypted data</param>
    /// <param name="out_len">Length of decrypted data</param>
    /// <param name="label">Hash of OAEP label</param>
    /// <param name="label_len">Length of hash of OAEP label</param>
    /// <param name="mgf1Algo">MGF1 algorithm</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_decrypt_oaep(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len,
        ReadOnlySpan<byte> label, nuint label_len, yh_algorithm mgf1Algo);

    /// <summary>
    /// Derive an ECDH key from a private EC key on the device and a provided public EC key
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the EC private key to use for ECDH derivation</param>
    /// <param name="in">Public key of another EC key-pair</param>
    /// <param name="in_len">Length of public key</param>
    /// <param name="out">Shared secret ECDH key</param>
    /// <param name="out_len">Length of the shared ECDH key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_derive_ecdh(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Delete an object in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="id">Object ID of the object to delete</param>
    /// <param name="type">Type of object to delete</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_delete_object(SafeSessionHandle session, ushort id,
        yh_object_type type);

    /// <summary>
    /// Export an object under wrap from the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrapping_key_id">Object ID of the Wrap Key to use to wrap the object</param>
    /// <param name="target_type">Type of the object to be exported</param>
    /// <param name="target_id">Object ID of the object to be exported</param>
    /// <param name="out">Wrapped data</param>
    /// <param name="out_len">Length of wrapped data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_export_wrapped(SafeSessionHandle session, ushort wrapping_key_id,
        yh_object_type target_type, ushort target_id, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Export an object under wrap from the device with the option to include the ED25519 seed
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrapping_key_id">Object ID of the Wrap Key to use to wrap the object</param>
    /// <param name="target_type">Type of the object to be exported</param>
    /// <param name="target_id">Object ID of the object to be exported</param>
    /// <param name="format">Format option (0=legacy, 1=include ED25519 seed)</param>
    /// <param name="out">Wrapped data</param>
    /// <param name="out_len">Length of wrapped data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_export_wrapped_ex(SafeSessionHandle session, ushort wrapping_key_id,
        yh_object_type target_type, ushort target_id, byte format, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import a wrapped object into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrapping_key_id">Object ID of the Wrap Key to use to unwrap the object</param>
    /// <param name="in">Wrapped data</param>
    /// <param name="in_len">Length of wrapped data</param>
    /// <param name="target_type">Type of the imported object</param>
    /// <param name="target_id">Object ID of the imported object</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_wrapped(SafeSessionHandle session, ushort wrapping_key_id,
        ReadOnlySpan<byte> @in, nuint in_len, out yh_object_type target_type, out ushort target_id);

    /// <summary>
    /// Export a (a)symmetric key material using an RSA wrap key
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrap_key_id">Object ID of the Wrap Key to use to wrap the object</param>
    /// <param name="target_type">Type of the target key object</param>
    /// <param name="target_id">Object ID of the target key object</param>
    /// <param name="aes">Algorithm of the ephemeral AES key</param>
    /// <param name="hash">Hash algorithm</param>
    /// <param name="mgf1">MGF1 algorithm</param>
    /// <param name="oaep_label">Label for the MGF1 algorithm</param>
    /// <param name="oaep_label_len">Label length</param>
    /// <param name="out">Wrapped key object bytes</param>
    /// <param name="out_len">Length of the wrapped key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_rsa_wrapped_key(SafeSessionHandle session, ushort wrap_key_id,
        yh_object_type target_type, ushort target_id, yh_algorithm aes,
        yh_algorithm hash, yh_algorithm mgf1,
        ReadOnlySpan<byte> oaep_label, nuint oaep_label_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Export an object using an RSA wrap key
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrap_key_id">Object ID of the Wrap Key to use to wrap the object</param>
    /// <param name="target_type">Type of the target object</param>
    /// <param name="target_id">Object ID of the target object</param>
    /// <param name="aes">Algorithm of the ephemeral AES key</param>
    /// <param name="hash">Hash algorithm</param>
    /// <param name="mgf1">MGF1 algorithm</param>
    /// <param name="oaep_label">Label for the MGF1 algorithm</param>
    /// <param name="oaep_label_len">Label length</param>
    /// <param name="out">Wrapped object bytes</param>
    /// <param name="out_len">Length of the wrapped object</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_export_rsa_wrapped(SafeSessionHandle session, ushort wrap_key_id,
        yh_object_type target_type, ushort target_id, yh_algorithm aes,
        yh_algorithm hash, yh_algorithm mgf1,
        ReadOnlySpan<byte> oaep_label, nuint oaep_label_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import an object using an RSA wrap key
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrapping_key_id">Object ID of the Wrap Key to use to unwrap the object</param>
    /// <param name="hash">Hash algorithm</param>
    /// <param name="mgf1">MGF1 algorithm</param>
    /// <param name="label">Label for the MGF1 algorithm</param>
    /// <param name="label_len">Label length</param>
    /// <param name="in">Wrapped object bytes</param>
    /// <param name="in_len">Length of the wrapped object</param>
    /// <param name="target_type">Type of the target object</param>
    /// <param name="target_id">Object ID of the target object</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_rsa_wrapped(SafeSessionHandle session, ushort wrapping_key_id,
        yh_algorithm hash, yh_algorithm mgf1,
        ReadOnlySpan<byte> label, nuint label_len,
        ReadOnlySpan<byte> @in, nuint in_len,
        out yh_object_type target_type, out ushort target_id);

    /// <summary>
    /// Import an (a)symmetric key using an RSA wrap key
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="wrapping_key_id">Object ID of the Wrap Key to use to unwrap the object</param>
    /// <param name="type">Type of object to import</param>
    /// <param name="target_id">Object ID of object to import</param>
    /// <param name="algo">Key algorithm of object to import</param>
    /// <param name="label">Label of object to import</param>
    /// <param name="domains">Domains of object to import</param>
    /// <param name="capabilities">Capabilities of object to import</param>
    /// <param name="hash">Hash algorithm</param>
    /// <param name="mgf1">MGF1 algorithm</param>
    /// <param name="oaep_label">Label for the MGF1 algorithm</param>
    /// <param name="oaep_label_len">Label length</param>
    /// <param name="in">Wrapped object bytes</param>
    /// <param name="in_len">Length of the wrapped object</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_put_rsa_wrapped_key(
        SafeSessionHandle session, ushort wrapping_key_id, yh_object_type type,
        ref ushort target_id, yh_algorithm algo, ReadOnlySpan<byte> label, ushort domains,
        in yh_capabilities capabilities, yh_algorithm hash, yh_algorithm mgf1,
        ReadOnlySpan<byte> oaep_label, nuint oaep_label_len, ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Import a Wrap Key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID the Wrap Key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the Wrap Key</param>
    /// <param name="domains">Domains where the Wrap Key will be operating within</param>
    /// <param name="capabilities">Capabilities of the Wrap Key</param>
    /// <param name="algorithm">Algorithm of the Wrap Key</param>
    /// <param name="delegated_capabilities">Delegated capabilities of the Wrap Key</param>
    /// <param name="in">the Wrap Key to import</param>
    /// <param name="in_len">Length of the Wrap Key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_wrap_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, in yh_capabilities delegated_capabilities,
        ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Import a public RSA key as a public wrap Key into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID the Wrap Key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the Wrap Key</param>
    /// <param name="domains">Domains where the Wrap Key will be operating within</param>
    /// <param name="capabilities">Capabilities of the Wrap Key</param>
    /// <param name="algorithm">Algorithm of the Public Wrap Key</param>
    /// <param name="delegated_capabilities">Delegated capabilities of the Wrap Key</param>
    /// <param name="in">the Public Wrap Key to import in PEM format</param>
    /// <param name="in_len">Length of the Wrap Key to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_public_wrap_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, in yh_capabilities delegated_capabilities,
        ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Generate a Wrap Key that can be used for export, import, wrap data and unwrap data in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Wrap Key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the Wrap Key</param>
    /// <param name="domains">Domains where the Wrap Key will be operating within</param>
    /// <param name="capabilities">Capabilities of the Wrap Key</param>
    /// <param name="algorithm">Algorithm used to generate the Wrap Key</param>
    /// <param name="delegated_capabilities">Delegated capabilitites of the Wrap Key</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_wrap_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, in yh_capabilities delegated_capabilities);

    /// <summary>
    /// Get audit logs from the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="unlogged_boot">Number of unlogged boot events</param>
    /// <param name="unlogged_auth">Number of unlogged authentication events</param>
    /// <param name="out">Log entries on the device</param>
    /// <param name="n_items">Number of log entries</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_log_entries(SafeSessionHandle session, out ushort unlogged_boot,
        out ushort unlogged_auth, Span<yh_log_entry> @out, out nuint n_items);

    /// <summary>
    /// Set the index of the last extracted log entry
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="index">index to set</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_set_log_index(SafeSessionHandle session, ushort index);

    /// <summary>
    /// Get an YH_OPAQUE object (like an X.509 certificate) from the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Opaque object</param>
    /// <param name="out">the retrieved Opaque object</param>
    /// <param name="out_len">Length of the retrieved Opaque object</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_opaque(SafeSessionHandle session, ushort object_id,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import an YH_OPAQUE object into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Opaque object</param>
    /// <param name="label">Label of the Opaque object</param>
    /// <param name="domains">Domains the Opaque object will be operating within</param>
    /// <param name="capabilities">Capabilities of the Opaque object</param>
    /// <param name="algorithm">Algorithm of the Opaque object</param>
    /// <param name="in">the Opaque object to import</param>
    /// <param name="in_len">Length of the Opaque object to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_opaque(SafeSessionHandle session, ref ushort object_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Get an YH_OPAQUE object from the device with an option to decompress the data
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Opaque object</param>
    /// <param name="out">the retrieved Opaque object</param>
    /// <param name="out_len">Length of the retrieved Opaque object</param>
    /// <param name="stored_len">Length of the stored opaque object</param>
    /// <param name="try_decompress">Try decompressing the object data before returning it</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_opaque_ex(SafeSessionHandle session, ushort object_id,
        Span<byte> @out, out nuint out_len, out nuint stored_len, [MarshalAs(UnmanagedType.U1)] bool try_decompress);

    /// <summary>
    /// Import an YH_OPAQUE object into the device with an option to compress the data before import
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Opaque object. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the Opaque object</param>
    /// <param name="domains">Domains the Opaque object will be operating within</param>
    /// <param name="capabilities">Capabilities of the Opaque object</param>
    /// <param name="algorithm">Algorithm of the Opaque object</param>
    /// <param name="in">the Opaque object to import</param>
    /// <param name="in_len">Length of the Opaque object to import</param>
    /// <param name="compress">Compression option for X509 certificates</param>
    /// <param name="import_len">Number of bytes imported</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_opaque_ex(SafeSessionHandle session, ref ushort object_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> @in, nuint in_len,
        yh_compress_option compress, out nuint import_len);

    /// <summary>
    /// Sign an SSH Certificate request
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key used to sign the request</param>
    /// <param name="template_id">Object ID of the template to use as a certificate template</param>
    /// <param name="sig_algo">Signature algorithm to use to sign the certificate request</param>
    /// <param name="in">Certificate request</param>
    /// <param name="in_len">Length of the certificate request</param>
    /// <param name="out">Signature</param>
    /// <param name="out_len">Length of the signature</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_ssh_certificate(SafeSessionHandle session, ushort key_id,
        ushort template_id, yh_algorithm sig_algo,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import an YH_AUTHENTICATION_KEY into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the imported key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="delegated_capabilities">Delegated capabilities of the key</param>
    /// <param name="key_enc">Long lived encryption key of the Authentication Key to import</param>
    /// <param name="key_enc_len">Length of the encryption key. Must be YH_KEY_LEN</param>
    /// <param name="key_mac">Long lived MAC key of the Authentication Key to import</param>
    /// <param name="key_mac_len">Length of the MAC key. Must be YH_KEY_LEN</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_authentication_key(
        SafeSessionHandle session, ref ushort key_id, ReadOnlySpan<byte> label, ushort domains,
        in yh_capabilities capabilities, in yh_capabilities delegated_capabilities,
        ReadOnlySpan<byte> key_enc, nuint key_enc_len,
        ReadOnlySpan<byte> key_mac, nuint key_mac_len);

    /// <summary>
    /// Import an YH_AUTHENTICATION_KEY with long lived keys derived from a password
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the key</param>
    /// <param name="domains">Domains to which the key belongs</param>
    /// <param name="capabilities">Capabilities of the key</param>
    /// <param name="delegated_capabilities">Delegated capabilities of the key</param>
    /// <param name="password">Password used to derive the long lived encryption key and MAC key</param>
    /// <param name="password_len">Length of password</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_authentication_key_derived(
        SafeSessionHandle session, ref ushort key_id, ReadOnlySpan<byte> label, ushort domains,
        in yh_capabilities capabilities, in yh_capabilities delegated_capabilities,
        ReadOnlySpan<byte> password, nuint password_len);

    /// <summary>
    /// Replace the long lived encryption key and MAC key associated with an YH_AUTHENTICATION_KEY
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key to replace</param>
    /// <param name="key_enc">New long lived encryption key</param>
    /// <param name="key_enc_len">Length of the new encryption key. Must be YH_KEY_LEN</param>
    /// <param name="key_mac">New long lived MAC key</param>
    /// <param name="key_mac_len">Length of the new MAC key. Must be YH_KEY_LEN</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_change_authentication_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> key_enc, nuint key_enc_len,
        ReadOnlySpan<byte> key_mac, nuint key_mac_len);

    /// <summary>
    /// Replace the long lived encryption key and MAC key with keys derived from a password
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key to replace</param>
    /// <param name="password">Password to derive the new encryption key and MAC key</param>
    /// <param name="password_len">Length of password</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_change_authentication_key_derived(SafeSessionHandle session,
        ref ushort key_id, ReadOnlySpan<byte> password, nuint password_len);

    /// <summary>
    /// Get a YH_TEMPLATE object from the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Template to get</param>
    /// <param name="out">The retrieved Template</param>
    /// <param name="out_len">Length of the retrieved Template</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_template(SafeSessionHandle session, ushort object_id,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Import a YH_TEMPLATE object into the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="object_id">Object ID of the Template. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the Template</param>
    /// <param name="domains">Domains the Template will be operating within</param>
    /// <param name="capabilities">Capabilities of the Template</param>
    /// <param name="algorithm">Algorithm of the Template</param>
    /// <param name="in">Template to import</param>
    /// <param name="in_len">Length of the Template to import</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_template(SafeSessionHandle session, ref ushort object_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Create a Yubico OTP AEAD using the provided data
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Otp-aead Key to use</param>
    /// <param name="key">OTP key</param>
    /// <param name="private_id">OTP private id</param>
    /// <param name="out">The created AEAD</param>
    /// <param name="out_len">Length of the created AEAD</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_create_otp_aead(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> private_id, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Create OTP AEAD from random data
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Otp-aead Key to use</param>
    /// <param name="out">The created AEAD</param>
    /// <param name="out_len">Length of the created AEAD</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_randomize_otp_aead(SafeSessionHandle session, ushort key_id,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Decrypt a Yubico OTP and return counters and time information
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the key used for decryption</param>
    /// <param name="aead">AEAD as created by yh_util_create_otp_aead or yh_util_randomize_otp_aead</param>
    /// <param name="aead_len">Length of AEAD</param>
    /// <param name="otp">OTP</param>
    /// <param name="useCtr">OTP use counter</param>
    /// <param name="sessionCtr">OTP session counter</param>
    /// <param name="tstph">OTP timestamp high</param>
    /// <param name="tstpl">OTP timestamp low</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_decrypt_otp(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> aead, nuint aead_len, ReadOnlySpan<byte> otp,
        out ushort useCtr, out byte sessionCtr, out byte tstph, out ushort tstpl);

    /// <summary>
    /// Rewrap an OTP AEAD from one YH_OTP_AEAD_KEY to another
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="id_from">Object ID of the AEAD Key to wrap from</param>
    /// <param name="id_to">Object ID of the AEAD Key to wrap to</param>
    /// <param name="aead_in">AEAD to unwrap</param>
    /// <param name="in_len">Length of AEAD</param>
    /// <param name="aead_out">The created AEAD</param>
    /// <param name="out_len">Length of output AEAD</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_rewrap_otp_aead(SafeSessionHandle session, ushort id_from,
        ushort id_to, ReadOnlySpan<byte> aead_in, nuint in_len,
        Span<byte> aead_out, out nuint out_len);

    /// <summary>
    /// Import an YH_OTP_AEAD_KEY used for Yubico OTP Decryption
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the AEAD Key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the AEAD Key</param>
    /// <param name="domains">Domains the AEAD Key will be operating within</param>
    /// <param name="capabilities">Capabilities of the AEAD Key</param>
    /// <param name="nonce_id">Nonce ID</param>
    /// <param name="in">AEAD Key to import</param>
    /// <param name="in_len">Length of AEAD Key to import. Must be 16, 24 or 32</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_import_otp_aead_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        uint nonce_id, ReadOnlySpan<byte> @in, nuint in_len);

    /// <summary>
    /// Generate an YH_OTP_AEAD_KEY for Yubico OTP decryption in the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the AEAD Key. 0 if the Object ID should be generated by the device</param>
    /// <param name="label">Label of the AEAD Key</param>
    /// <param name="domains">Domains the AEAD Key will be operating within</param>
    /// <param name="capabilities">Capabilities of the AEAD Key</param>
    /// <param name="algorithm">Algorithm used to generate the AEAD Key</param>
    /// <param name="nonce_id">Nonce ID</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_generate_otp_aead_key(SafeSessionHandle session, ref ushort key_id,
        ReadOnlySpan<byte> label, ushort domains, in yh_capabilities capabilities,
        yh_algorithm algorithm, uint nonce_id);

    /// <summary>
    /// Get attestation of an Asymmetric Key in the form of an X.509 certificate
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Asymmetric Key to attest</param>
    /// <param name="attest_id">Object ID for the key used to sign the attestation certificate</param>
    /// <param name="out">The attestation certificate</param>
    /// <param name="out_len">Length of the attestation certificate</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_sign_attestation_certificate(SafeSessionHandle session, ushort key_id,
        ushort attest_id, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Set a device-global option
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="option">Option to set</param>
    /// <param name="len">Length of option value</param>
    /// <param name="val">Option value</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_set_option(SafeSessionHandle session, yh_option option, nuint len,
        Span<byte> val);

    /// <summary>
    /// Get a device-global option
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="option">Option to get</param>
    /// <param name="out">Option value</param>
    /// <param name="out_len">Length of option value</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_option(SafeSessionHandle session, yh_option option,
        Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Report currently free storage
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="total_records">Total number of records</param>
    /// <param name="free_records">Number of free records</param>
    /// <param name="total_pages">Total number of pages</param>
    /// <param name="free_pages">Number of free pages</param>
    /// <param name="page_size">Page size in bytes</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_get_storage_info(SafeSessionHandle session,
        out ushort total_records, out ushort free_records, out ushort total_pages,
        out ushort free_pages, out ushort page_size);

    /// <summary>
    /// Encrypt (wrap) data using a YH_WRAP_KEY
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Wrap Key to use</param>
    /// <param name="in">Data to wrap</param>
    /// <param name="in_len">Length of data to wrap</param>
    /// <param name="out">Wrapped data</param>
    /// <param name="out_len">Length of the wrapped data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_wrap_data(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Decrypt (unwrap) data using a YH_WRAP_KEY
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Wrap Key to use</param>
    /// <param name="in">Wrapped data</param>
    /// <param name="in_len">Length of wrapped data</param>
    /// <param name="out">Unwrapped data</param>
    /// <param name="out_len">Length of unwrapped data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_unwrap_data(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Encrypt data using a AES YH_SYMMETRIC_KEY in ECB mode
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Symmetric Key to use</param>
    /// <param name="in">Plaintext data</param>
    /// <param name="in_len">Length of plaintext data</param>
    /// <param name="out">Encrypted data</param>
    /// <param name="out_len">Length of encrypted data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_encrypt_aes_ecb(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Decrypt data using a AES YH_SYMMETRIC_KEY in ECB mode
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Symmetric Key to use</param>
    /// <param name="in">Encrypted data</param>
    /// <param name="in_len">Length of encrypted data</param>
    /// <param name="out">Decrypted data</param>
    /// <param name="out_len">Length of decrypted data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_decrypt_aes_ecb(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Encrypt data using an AES YH_SYMMETRIC_KEY in CBC mode
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Symmetric Key to use</param>
    /// <param name="iv">The 16-byte initialization vector</param>
    /// <param name="in">Plaintext data</param>
    /// <param name="in_len">Length of plaintext data</param>
    /// <param name="out">Encrypted data</param>
    /// <param name="out_len">Length of encrypted data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_encrypt_aes_cbc(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> iv, ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Decrypt data using an AES YH_SYMMETRIC_KEY in CBC mode
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="key_id">Object ID of the Symmetric Key to use</param>
    /// <param name="iv">The 16-byte initialization vector</param>
    /// <param name="in">Encrypted data</param>
    /// <param name="in_len">Length of encrypted data</param>
    /// <param name="out">Decrypted data</param>
    /// <param name="out_len">Length of decrypted data</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_decrypt_aes_cbc(SafeSessionHandle session, ushort key_id,
        ReadOnlySpan<byte> iv, ReadOnlySpan<byte> @in, nuint in_len, Span<byte> @out, out nuint out_len);

    /// <summary>
    /// Pad data using PKCS #7 padding
    /// </summary>
    /// <param name="buffer">Data to be padded</param>
    /// <param name="length">Pointer to the current length of the data</param>
    /// <param name="size">The maximum size of the buffer</param>
    /// <param name="block_size">The block size of the cipher used for encryption, in bytes</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_pad_pkcs7(Span<byte> buffer, ref nuint length, nuint size,
        byte block_size);

    /// <summary>
    /// Unpad data that has PKCS #7 padding
    /// </summary>
    /// <param name="buffer">Data to be unpadded</param>
    /// <param name="length">Pointer to the current length of the data</param>
    /// <param name="block_size">The block size of the cipher used for encryption, in bytes</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_unpad_pkcs7(Span<byte> buffer, ref nuint length, byte block_size);

    /// <summary>
    /// Blink the LED of the device to identify it
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="seconds">Number of seconds to blink</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_blink_device(SafeSessionHandle session, byte seconds);

    /// <summary>
    /// Factory reset the device
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_util_reset_device(SafeSessionHandle session);

    /// <summary>
    /// Get the session ID
    /// </summary>
    /// <param name="session">Authenticated session to use</param>
    /// <param name="sid">Session ID</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_get_session_id(SafeSessionHandle session, out byte sid);

    /// <summary>
    /// Check if the connector has a device connected
    /// </summary>
    /// <param name="connector">Connector currently in use</param>
    /// <returns>True if a device is connected</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_connector_has_device(SafeConnectorHandle connector);

    /// <summary>
    /// Get the connector version
    /// </summary>
    /// <param name="connector">Connector currently in use</param>
    /// <param name="major">Connector major version</param>
    /// <param name="minor">Connector minor version</param>
    /// <param name="patch">Connector patch version</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_get_connector_version(SafeConnectorHandle connector,
        out byte major, out byte minor, out byte patch);

    /// <summary>
    /// Get connector address
    /// </summary>
    /// <param name="connector">Connector currently in use</param>
    /// <param name="address">Pointer to the connector address as string</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_get_connector_address(SafeConnectorHandle connector, out nint address);

    /// <summary>
    /// Convert capability string to byte array
    /// </summary>
    /// <param name="capability">String of capabilities separated by ',', ':' or '|'</param>
    /// <param name="result">Array of capabilities</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_string_to_capabilities(ReadOnlySpan<byte> capability,
        out yh_capabilities result);

    /// <summary>
    /// Convert an array of capabilities into strings separated by ','
    /// </summary>
    /// <param name="num">Array of capabilities</param>
    /// <param name="result">Array of the capabilies as strings</param>
    /// <param name="n_result">Number of elements in result</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_capabilities_to_strings(in yh_capabilities num,
        out nint result, out nuint n_result);

    /// <summary>
    /// Check if a capability is set
    /// </summary>
    /// <param name="capabilities">Array of capabilities</param>
    /// <param name="capability">Capability to check as a string</param>
    /// <returns>True if the capability is in capabilities</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_check_capability(in yh_capabilities capabilities,
        ReadOnlySpan<byte> capability);

    /// <summary>
    /// Merge two sets of capabilities
    /// </summary>
    /// <param name="a">Array of capabilities</param>
    /// <param name="b">Array of capabilities</param>
    /// <param name="result">Resulting array of capabilities</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_merge_capabilities(in yh_capabilities a, in yh_capabilities b,
        out yh_capabilities result);

    /// <summary>
    /// Filter one set of capabilities with another
    /// </summary>
    /// <param name="capabilities">Array of capabilities</param>
    /// <param name="filter">Array of capabilities</param>
    /// <param name="result">Resulting array of capabilities</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_filter_capabilities(in yh_capabilities capabilities,
        in yh_capabilities filter, out yh_capabilities result);

    /// <summary>
    /// Check if an algorithm is a supported Symmetric Key AES algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm to check</param>
    /// <returns>True if the algorithm is one of the supported AES algorithms</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_is_aes(yh_algorithm algorithm);

    /// <summary>
    /// Check if an algorithm is a supported RSA algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm to check</param>
    /// <returns>True if the algorithm is one of the supported RSA algorithms</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_is_rsa(yh_algorithm algorithm);

    /// <summary>
    /// Check if an algorithm is a supported Elliptic Curve algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm to check</param>
    /// <returns>True if the algorithm is one of the supported EC algorithms</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_is_ec(yh_algorithm algorithm);

    /// <summary>
    /// Check if an algorithm is a supported ED algorithm
    /// </summary>
    /// <param name="algorithm">algorithm</param>
    /// <returns>True if the algorithm is #YH_ALGO_EC_ED25519</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_is_ed(yh_algorithm algorithm);

    /// <summary>
    /// Check if algorithm is a supported HMAC algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm to check</param>
    /// <returns>True if the algorithm is one of the supported HMAC algorithms</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_is_hmac(yh_algorithm algorithm);

    /// <summary>
    /// Get the expected key length of a key generated by the given algorithm
    /// </summary>
    /// <param name="algorithm">Algorithm to check</param>
    /// <param name="result">Expected bitlength of a key generated by the algorithm</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_get_key_bitlength(yh_algorithm algorithm, out nuint result);

    /// <summary>
    /// Convert an algorithm to its string representation
    /// </summary>
    /// <param name="algo">Algorithm to convert</param>
    /// <param name="result">The algorithm as a String</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_algo_to_string(yh_algorithm algo, out nint result);

    /// <summary>
    /// Convert a string to an algorithm's numeric value
    /// </summary>
    /// <param name="string">Algorithm as string</param>
    /// <param name="algo">Algorithm numeric value</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_string_to_algo(ReadOnlySpan<byte> @string, out yh_algorithm algo);

    /// <summary>
    /// Convert a yh_object_type to its string representation
    /// </summary>
    /// <param name="type">Type to convert</param>
    /// <param name="result">The type as a String</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_type_to_string(yh_object_type type, out nint result);

    /// <summary>
    /// Convert a string to a type's numeric value
    /// </summary>
    /// <param name="string">Type as a String</param>
    /// <param name="type">Type numeric value</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_string_to_type(ReadOnlySpan<byte> @string, out yh_object_type type);

    /// <summary>
    /// Convert a string to an option's numeric value
    /// </summary>
    /// <param name="string">Option as string</param>
    /// <param name="option">Option numeric value</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_string_to_option(ReadOnlySpan<byte> @string, out yh_option option);

    /// <summary>
    /// Verify an array of log entries
    /// </summary>
    /// <param name="logs">Array of log entries</param>
    /// <param name="n_items">number of log entries</param>
    /// <param name="last_previous_log">Optional pointer to the entry before the first entry</param>
    /// <returns>True if verification succeeds</returns>
    [LibraryImport(nameof(libyubihsm))]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool yh_verify_logs(Span<yh_log_entry> logs, nuint n_items,
        in yh_log_entry last_previous_log);

    /// <summary>
    /// Convert a string to a domain's numeric value
    /// </summary>
    /// <param name="domains">String of domains</param>
    /// <param name="result">Resulting parsed domains as an unsigned int</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_string_to_domains(ReadOnlySpan<byte> domains, out ushort result);

    /// <summary>
    /// Convert domains parameter to its String representation
    /// </summary>
    /// <param name="domains">Encoded domains</param>
    /// <param name="string">Domains as a string</param>
    /// <param name="max_len">Maximum length of the string</param>
    /// <returns><see cref="yh_rc.YHR_SUCCESS"/> if successful</returns>
    [LibraryImport(nameof(libyubihsm))]
    public static partial yh_rc yh_domains_to_string(ushort domains, Span<byte> @string, nuint max_len);
}
