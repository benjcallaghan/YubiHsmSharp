global using System;
global using System.Collections.Generic;
global using System.Linq;
global using System.Runtime.InteropServices;
global using System.Text;
global using System.Threading;

namespace YubiHsmSharp;

/// <summary>
/// Assembly constants and metadata for YubiHsmSharp.
/// </summary>
public static class AssemblyInfo
{
    /// <summary>
    /// The name of the native YubiHSM library.
    /// </summary>
    public const string NativeLibrary = "libyubihsm";

    /// <summary>
    /// The default YubiHSM password used for authentication.
    /// </summary>
    public const string DefaultPassword = "password";

    /// <summary>
    /// Default timeout in milliseconds for device connections.
    /// </summary>
    public const int DefaultConnectTimeout = 0; // 0 = no timeout
}
