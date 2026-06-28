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

using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Represents an ISO 9564 Format 0 PIN Block, encrypted with DES ECB.
/// </summary>
public readonly struct Format0PinBlock
{
    private readonly byte[] pinBlock;

    /// <summary>
    /// Encapsulates an encrypted PIN block as a Format 4 PIN Block.
    /// </summary>
    /// <remarks>
    /// This constructor takes ownership of the <paramref name="pinBlock"/> array.
    /// </remarks>
    /// <param name="pinBlock">The pin block to parse</param>
    public Format0PinBlock(byte[] pinBlock)
    {
        this.pinBlock = pinBlock;
    }

    /// <summary>
    /// Encrypts a PIN into a Format 0 PIN Block.
    /// </summary>
    /// <param name="cipher">The DES cipher for encryption.</param>
    /// <param name="pinEncryptionKey">The DES encryption key.</param>
    /// <param name="pin">The PIN to encipher.</param>
    /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
    /// <returns>A Format 0 PIN Block containing the enciphered PIN.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="cipher"/> or <paramref name="pinEncryptionKey"/> are not compatible with DES.</exception>
    public static Format0PinBlock Encrypt(IBlockCipher cipher, KeyParameter pinEncryptionKey, string pin, string primaryAccountNumber)
    {
        Span<byte> pinBlock = stackalloc byte[8];
        GeneratePinBlock(pin, pinBlock);

        Span<byte> panBlock = stackalloc byte[8];
        GeneratePanBlock(primaryAccountNumber, panBlock);

        Bytes.XorTo(pinBlock.Length, panBlock, pinBlock);

        cipher.Init(forEncryption: true, pinEncryptionKey);
        byte[] encryptedBlock = new byte[cipher.GetBlockSize()];
        int written = cipher.ProcessBlock(pinBlock, encryptedBlock);
        Debug.Assert(written == encryptedBlock.Length);

        return new Format0PinBlock(encryptedBlock);
    }

    /// <summary>
    /// Decrypts the Format 0 PIN Block and extracts the clear PIN.
    /// </summary>
    /// <param name="cipher">The DES cipher to use for decryption.</param>
    /// <param name="pinEncryptionKey">The DES encryption key.</param>
    /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
    /// <returns>The deciphered PIN.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="cipher"/> or <paramref name="pinEncryptionKey"/> are not compatible with DES.</exception>
    public string Decrypt(IBlockCipher cipher, KeyParameter pinEncryptionKey, string primaryAccountNumber)
    {
        cipher.Init(forEncryption: false, pinEncryptionKey);
        Span<byte> pinBlock = stackalloc byte[8];

        int written = cipher.ProcessBlock(this.pinBlock, pinBlock);
        Debug.Assert(written == pinBlock.Length);

        Span<byte> panBlock = stackalloc byte[8];
        GeneratePanBlock(primaryAccountNumber, panBlock);
        Bytes.XorTo(pinBlock.Length, panBlock, pinBlock);

        return ExtractPinFromBlock(pinBlock);
    }

    private static string ExtractPinFromBlock(Span<byte> pinBlock)
    {
        int header = pinBlock[0] >> 4;
        if (header != 0)
        {
            throw new ArgumentException("The PIN block is not Format 0.", nameof(pinBlock));
        }

        int pinLength = pinBlock[0] & 0x0F;
        int pinBytes = pinLength / 2;
        if (pinLength % 2 == 1)
        {
            // One extra byte is needed (high-nibble only)
            pinBytes += 1;
        }

#if NET9_0_OR_GREATER
        Span<byte> stringState = pinBlock.Slice(1, pinBytes);
#else
        Memory<byte> stringState = pinBlock.Slice(1, pinBytes).ToArray();
#endif

        return String.Create(pinLength, stringState, static (pin, state) =>
        {
#if NET9_0_OR_GREATER
            Span<byte> pinBlock = state;
#else
            Span<byte> pinBlock = state.Span;
#endif
            int pinIndex = 0;
            int blockLength = pin.Length % 2 == 0 ? pinBlock.Length : pinBlock.Length - 1; // Treat the last (half) byte special.

            for (int blockIndex = 0; blockIndex < blockLength; blockIndex++)
            {
                pin[pinIndex++] = (char)((pinBlock[blockIndex] >> 4) + '0');
                pin[pinIndex++] = (char)((pinBlock[blockIndex] & 0x0F) + '0');
            }

            if (blockLength != pinBlock.Length)
            {
                // Odd number of digits, so only keep the high nibble here.
                pin[pinIndex++] = (char)((pinBlock[^1] >> 4) + '0');
            }
        });
    }

    private static void GeneratePinBlock(string pin, Span<byte> pinBlock)
    {
        Debug.Assert(pinBlock.Length == 8);

        int blockIndex = 0;
        pinBlock[blockIndex++] = (byte)(0x00 | pin.Length); // Block Format 0 + PIN Length

        // PIN digits, 4 bits per digit
        for (int pinIndex = 0; pinIndex < pin.Length - 1; pinIndex += 2)
        {
            // pinIndex is an even number with bounds [0, pin.Length - 1)
            // pinIndex+1 is an odd number with bounds [1, pin.Length)
            byte leftNibble = (byte)((pin[pinIndex] - '0') << 4);
            byte rightNibble = (byte)(pin[pinIndex + 1] - '0');
            pinBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        if (pin.Length % 2 == 1)
        {
            // There is one digit left over, which should be combined with the hex digit F.
            byte leftNibble = (byte)((pin[^1] - '0') << 4);
            byte rightNibble = 0x0F;
            pinBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        // Fill remaining digits in first half with hex digit F.
        pinBlock[blockIndex..8].Fill(0xFF);
    }

    private static void GeneratePanBlock(string primaryAccountNumber, Span<byte> panBlock)
    {
        Debug.Assert(panBlock.Length == 8);

        int blockIndex = 0;
        panBlock[blockIndex++] = 0;
        panBlock[blockIndex++] = 0;

        ReadOnlySpan<char> pan = primaryAccountNumber.AsSpan(^13..^1); // Last 12 digits, excluding check digit.

        // PAN digits, 4 bits per digit
        for (int panIndex = 0; panIndex < pan.Length - 1; panIndex += 2)
        {
            // panIndex is an odd number with bounds [1, pan.Length - 1)
            // panIndex+1 is an even number with bounds [2, pan.Length)
            byte leftNibble = (byte)((pan[panIndex] - '0') << 4);
            byte rightNibble = (byte)(pan[panIndex + 1] - '0');
            panBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }
    }
}