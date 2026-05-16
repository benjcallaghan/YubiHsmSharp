namespace YubiHsmSharp;

/// <summary>
/// Counters decrypted from a Yubico OTP.
/// </summary>
/// <param name="UseCounter">The use counter.</param>
/// <param name="SessionCounter">The session counter.</param>
/// <param name="TimestampHigh">The high part of the timestamp.</param>
/// <param name="TimestampLow">The low part of the timestamp.</param>
public record class OtpCounters(ushort UseCounter, byte SessionCounter, byte TimestampHigh, ushort TimestampLow);
