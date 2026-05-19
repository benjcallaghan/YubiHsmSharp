using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Standalone utilities for interacting with raw keys.
/// </summary>
public static class KeyUtils
{
    /// <summary>
    /// Generates a key check value (KCV) for the given AES key.
    /// </summary>
    /// <remarks>
    /// This method is useful for verifying that a hand-typed encryption key was entered correctly.
    /// Assuming that the encryption key is accompanied by a pre-existing KCV, a robust program should
    /// generate its own KCV using the hand-typed key and display the KCV to the user, who should then
    /// verify that the KCV is accurate. If the KCVs are different, then a typo is present in the key.
    /// </remarks>
    /// <param name="aesKey">The key to check.</param>
    /// <param name="keyCheckValue">A buffer to hold the generated KCV.</param>
    /// <returns>The number of bytes written to <paramref name="keyCheckValue"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="keyCheckValue"/> is too small.</exception>
    public static int AesKeyCheckValue(ReadOnlySpan<byte> aesKey, Span<byte> keyCheckValue)
    {
        const int kcvSize = 3;
        if (keyCheckValue.Length < kcvSize)
        {
            throw new ArgumentException($"The output buffer for the key check value must be at least {kcvSize} bytes.", nameof(keyCheckValue));
        }

        CMac cmac = new(AesUtilities.CreateEngine());
        cmac.Init(new KeyParameter(aesKey));

        int blockSize = cmac.GetMacSize();
        Span<byte> mac = stackalloc byte[blockSize];
        mac.Clear(); // Ensure all zeros.

        cmac.BlockUpdate(mac);
        cmac.DoFinal(mac);

        mac[..kcvSize].CopyTo(keyCheckValue);
        return kcvSize;
    }

    /// <summary>
    /// Combines three key components into a usable encryption key.
    /// </summary>
    /// <param name="c1">The first key component.</param>
    /// <param name="c2">The second key component.</param>
    /// <param name="c3">The third key component.</param>
    /// <param name="key">The combined encryption key.</param>
    /// <returns>The number of bytes written to <paramref name="key"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if the key components are different lengths or if <paramref name="key"/> is too small.</exception>
    public static int CombineComponents(ReadOnlySpan<byte> c1, ReadOnlySpan<byte> c2, ReadOnlySpan<byte> c3, Span<byte> key)
        => Xor(c1, c2, c3, key);

    /// <summary>
    /// Performs the XOR operation on each byte of each component, storing the value in result.
    /// </summary>
    /// <param name="c1">The first component.</param>
    /// <param name="c2">The second component.</param>
    /// <param name="result">The result of XOR'ing each byte.</param>
    /// <returns>The number of bytes written to <paramref name="result"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if the components are different lengths or if <paramref name="result"/> is too small.</exception>
    public static int Xor(ReadOnlySpan<byte> c1, ReadOnlySpan<byte> c2, Span<byte> result)
    {
        if (c1.Length != c2.Length)
        {
            throw new ArgumentException("All key components must be the same length.");
        }
        if (result.Length < c1.Length)
        {
            throw new ArgumentException("The key buffer must be at least as long as the key components.", nameof(result));
        }

        for (int i = 0; i < c1.Length; i++)
        {
            result[i] = (byte)(c1[i] ^ c2[i]);
        }

        return c1.Length;
    }

    /// <summary>
    /// Performs the XOR operation on each byte of each component, storing the value in result.
    /// </summary>
    /// <param name="c1">The first component.</param>
    /// <param name="c2">The second component.</param>
    /// <param name="c3">The third component.</param>
    /// <param name="result">The result of XOR'ing each byte.</param>
    /// <returns>The number of bytes written to <paramref name="result"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if the components are different lengths or if <paramref name="result"/> is too small.</exception>
    public static int Xor(ReadOnlySpan<byte> c1, ReadOnlySpan<byte> c2, ReadOnlySpan<byte> c3, Span<byte> result)
    {
        if (c1.Length != c2.Length || c2.Length != c3.Length)
        {
            throw new ArgumentException("All key components must be the same length.");
        }
        if (result.Length < c1.Length)
        {
            throw new ArgumentException("The key buffer must be at least as long as the key components.", nameof(result));
        }

        for (int i = 0; i < c1.Length; i++)
        {
            result[i] = (byte)(c1[i] ^ c2[i] ^ c3[i]);
        }

        return c1.Length;
    }
}
