namespace YubiHsmSharp;

/// <summary>
/// Utility for converting YubiHSM error codes to exceptions.
/// </summary>
internal static class ErrorHandler
{
    /// <summary>
    /// Check a YubiHSM return code and throw an exception if it indicates failure.
    /// </summary>
    /// <param name="returnCode">Return code from a P/Invoke call.</param>
    /// <param name="context">Context description for the error message.</param>
    /// <exception cref="YubiHsmException">Thrown for library-level errors.</exception>
    /// <exception cref="YubiHsmDeviceException">Thrown for device-level errors.</exception>
    public static void ThrowIfError(YhReturnCode returnCode, string context = "")
    {
        if (returnCode == YhReturnCode.Success)
            return;

        string errorMessage = GetErrorMessage(returnCode, context);

        if ((int)returnCode < 0)
        {
            // Library error
            throw new YubiHsmException(errorMessage);
        }
        else
        {
            // Device error
            throw new YubiHsmDeviceException(returnCode, errorMessage);
        }
    }

    /// <summary>
    /// Get a human-readable error message for a return code.
    /// </summary>
    private static string GetErrorMessage(YhReturnCode returnCode, string context)
    {
        string nativeMessage = NativeMethods.yh_strerror(returnCode) ?? "Unknown error";
        
        if (string.IsNullOrEmpty(context))
            return nativeMessage;

        return $"{context}: {nativeMessage}";
    }

    /// <summary>
    /// Map a device return code to the appropriate exception type.
    /// </summary>
    public static void ThrowDeviceError(YhReturnCode returnCode, string context = "")
    {
        if (returnCode == YhReturnCode.Success)
            return;

        string message = GetErrorMessage(returnCode, context);
        throw new YubiHsmDeviceException(returnCode, message);
    }
}
