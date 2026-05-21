using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Utilities;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Represents an ISO 9564-1:2017 Format 4 PIN Block, encrypted with AES-128 ECB.
/// </summary>
public readonly struct Format4PinBlock
{
    private readonly byte[] pinBlock;

    /// <summary>
    /// Encapsulates an encrypted PIN block as a Format 4 PIN Block.
    /// </summary>
    /// <remarks>
    /// This constructor takes ownership of the <paramref name="pinBlock"/> array.
    /// </remarks>
    /// <param name="pinBlock">The pin block to parse</param>
    public Format4PinBlock(byte[] pinBlock)
    {
        this.pinBlock = pinBlock;
    }

    /// <summary>
    /// Encrypts a PIN into a Format 4 PIN Block.
    /// </summary>
    /// <param name="cipher">The AES cipher for encryption.</param>
    /// <param name="pinEncryptionKey">The AES encryption key.</param>
    /// <param name="random">A random bytes generator to pad the pin block.</param>
    /// <param name="pin">The PIN to encipher.</param>
    /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN</param>
    /// <returns>A Format 4 PIN Block containing the enciphered PIN.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="cipher"/> or <paramref name="pinEncryptionKey"/> are not compatible with AES-128.</exception>
    public static Format4PinBlock Encrypt(IBlockCipher cipher, KeyParameter pinEncryptionKey, IRandomGenerator random, string pin, string primaryAccountNumber)
    {
        if (!cipher.AlgorithmName.Contains("aes", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException("Only AES ciphers are supported for PIN Block Format 4.", nameof(cipher));
        }
        if (pinEncryptionKey.KeyLength != 16)
        {
            throw new ArgumentException("Only 128-bit keys are supported for PIN Block Format 4.", nameof(pinEncryptionKey));
        }

        Span<byte> pinBlock = stackalloc byte[16];
        GeneratePinBlock(random, pin, pinBlock);

        Span<byte> panBlock = stackalloc byte[16];
        GeneratePanBlock(primaryAccountNumber, panBlock);

        cipher.Init(forEncryption: true, pinEncryptionKey);
        byte[] encryptedBlock = new byte[cipher.GetBlockSize()];
        int written = cipher.ProcessBlock(pinBlock, encryptedBlock);
        Debug.Assert(written == encryptedBlock.Length);

        Bytes.XorTo(encryptedBlock.Length, panBlock, encryptedBlock);

        written = cipher.ProcessBlock(encryptedBlock, encryptedBlock);
        Debug.Assert(written == encryptedBlock.Length);

        return new Format4PinBlock(encryptedBlock);
    }

    private static void GeneratePinBlock(IRandomGenerator random, string pin, Span<byte> pinBlock)
    {
        Debug.Assert(pinBlock.Length == 16);

        int blockIndex = 0;
        pinBlock[blockIndex++] = (byte)(0x40 | pin.Length); // Block Format 4 + PIN Length

        // PIN digits, 4 bits per digit
        for (int pinIndex = 0; pinIndex < pin.Length - 1; pinIndex += 2)
        {
            // pinIndex is an even number with bounds [0, pin.Length - 1)
            // pinIndex+1 is an odd number with bounds [1, pin.Length)
            byte leftNibble = (byte)(pin[pinIndex] - '0' << 4);
            byte rightNibble = (byte)(pin[pinIndex + 1] - '0');
            pinBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        if (pin.Length % 2 == 1)
        {
            // There is one digit left over, which should be combined with the hex digit A.
            byte leftNibble = (byte)(pin[^1] - '0' << 4);
            byte rightNibble = 0x0A;
            pinBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        // Fill remaining digits in first half with hex digit A.
        pinBlock[blockIndex..8].Fill(0xAA);

        // Add random values for remaining digits.
        random.NextBytes(pinBlock[8..]);
    }

    private static void GeneratePanBlock(string primaryAccountNumber, Span<byte> panBlock)
    {
        Debug.Assert(panBlock.Length == 16);

        int blockIndex = 0;
        int normalizedLength = primaryAccountNumber.Length - 12;
        panBlock[blockIndex++] = (byte)((normalizedLength << 4) | (primaryAccountNumber[0] - '0'));

        // PAN digits, 4 bits per digit
        for (int panIndex = 1; panIndex < primaryAccountNumber.Length - 1; panIndex += 2)
        {
            // panIndex is an odd number with bounds [1, pan.Length - 1)
            // panIndex+1 is an even number with bounds [2, pan.Length)
            byte leftNibble = (byte)(primaryAccountNumber[panIndex] - '0' << 4);
            byte rightNibble = (byte)(primaryAccountNumber[panIndex + 1] - '0');
            panBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        if (primaryAccountNumber.Length % 2 == 0)
        {
            // There is one digit left over, which should be combined with the hex digit 0.
            byte leftNibble = (byte)(primaryAccountNumber[^1] - '0' << 4);
            byte rightNibble = 0x00;
            panBlock[blockIndex++] = (byte)(leftNibble | rightNibble);
        }

        // Fill remaining digits with hex digit 0.
        panBlock[blockIndex..].Clear();
    }
}