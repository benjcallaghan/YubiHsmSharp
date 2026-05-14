using System.Runtime.InteropServices;
using static YubiHsmSharp.yubihsm;

namespace YubiHsmSharp;

/// <summary>
/// The exception that is thrown when a native YubiHSM method returns an error code.
/// </summary>
public class YubiHsmException : Exception
{
    internal YubiHsmException(yh_rc err) : base(GetErrorMessage(err))
    {        
    }

    private static string GetErrorMessage(yh_rc err)
    {
        nint message = yh_strerror(err);
        return Marshal.PtrToStringUTF8(message) ?? String.Empty;
    }

    internal static void ThrowIfError(yh_rc err)
    {
        if (err != yh_rc.YHR_SUCCESS)
        {
            throw new YubiHsmException(err);
        }
    }
}