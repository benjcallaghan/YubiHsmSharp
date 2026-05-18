using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Standalone utilities for interacting with raw keys.
/// </summary>
public class KeyUtils
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
    public int AesKeyCheckValue(ReadOnlySpan<byte> aesKey, Span<byte> keyCheckValue)
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
}
