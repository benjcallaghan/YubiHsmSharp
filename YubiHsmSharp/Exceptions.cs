namespace YubiHsmSharp;

/// <summary>
/// Base exception for YubiHsmSharp library errors.
/// </summary>
public class YubiHsmException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="YubiHsmException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public YubiHsmException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="YubiHsmException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public YubiHsmException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception raised when a YubiHSM device operation fails.
/// </summary>
public class YubiHsmDeviceException : YubiHsmException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="YubiHsmDeviceException"/> class.
    /// </summary>
    /// <param name="errorCode">The YubiHSM error code.</param>
    /// <param name="message">The error message.</param>
    public YubiHsmDeviceException(YhReturnCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets the YubiHSM error code.
    /// </summary>
    public YhReturnCode ErrorCode { get; }
}
