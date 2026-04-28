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
///   Debug.Assert(yh_init() == YHR_SUCCESS);
///   Debug.Assert(yh_init_connector("http://localhost:12345", out SafeConnectorHandle connector) == YHR_SUCCESS);
///   Debug.Assert(yh_connect(connector, 0) == YHR_SUCCESS);
///   Debug.Assert(yh_create_session_derived(connector, 1, YH_DEFAULT_PASSWORD, YH_DEFAULT_PASSWORD.Length,
///     false, out SafeSessionHandle session) == YHR_SUCCESS);
///   Debug.Assert(yh_util_get_pseudo_random(session, dataLen, data, out dataLen) == YHR_SUCCESS);
///   Debug.Assert(dataLen == data.Length);
///   Debug.Assert(yh_util_close_session(session) == YHR_SUCCESS);
///   Debug.Assert(yh_destroy_session(ref session) == YHR_SUCCESS);
///   Debug.Assert(yh_disconnect(connector) == YHR_SUCCESS);
/// }
/// </code>
/// </example>
/// <seealso>yubihsm.h</seealso> 
public static class yubihsm
{

}
