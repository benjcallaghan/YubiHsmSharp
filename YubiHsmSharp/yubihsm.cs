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
}
