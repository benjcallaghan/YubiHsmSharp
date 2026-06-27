/*
 * Copyright 2026 Benjamin Callaghan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Standalone utilities for interacting with raw keys.
/// </summary>
public static class KeyUtils
{
    /// <summary>
    /// Generates a key check value (KCV) for the given key.
    /// </summary>
    /// <remarks>
    /// This method is useful for verifying that a hand-typed encryption key was entered correctly.
    /// Assuming that the encryption key is accompanied by a pre-existing KCV, a robust program should
    /// generate its own KCV using the hand-typed key and display the KCV to the user, who should then
    /// verify that the KCV is accurate. If the KCVs are different, then a typo is present in the key.
    /// </remarks>
    /// <param name="cipher">The <see cref="IBlockCipher"/> associated with the key.</param>
    /// <param name="key">The key to check.</param>
    /// <param name="keyCheckValue">A buffer to hold the generated KCV.</param>
    /// <returns>The number of bytes written to <paramref name="keyCheckValue"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="keyCheckValue"/> is too small.</exception>
    public static int KeyCheckValue(IBlockCipher cipher, ReadOnlySpan<byte> key, Span<byte> keyCheckValue)
    {
        const int kcvSize = 3;
        if (keyCheckValue.Length < kcvSize)
        {
            throw new ArgumentException($"The output buffer for the key check value must be at least {kcvSize} bytes.", nameof(keyCheckValue));
        }

        CMac cmac = new(cipher);
        cmac.Init(new KeyParameter(key));

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
    {
        if (c1.Length != c2.Length || c2.Length != c3.Length)
        {
            throw new ArgumentException("All key components must be the same length.");
        }
        if (key.Length < c1.Length)
        {
            throw new ArgumentException("The key buffer must be at least as long as the key components.", nameof(key));
        }

        Bytes.Xor(c1.Length, c1, c2, key);
        Bytes.XorTo(c1.Length, c3, key);
        return c1.Length;
    }
}
