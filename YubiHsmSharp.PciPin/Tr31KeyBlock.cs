using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Represents a TR-31 Key Block, with header fields parsed and verified.
/// </summary>
public readonly struct TR31KeyBlock
{
    private readonly byte[] keyBlock;

    /// <summary>
    /// Parses key block header data and captures encrypted key data and authentication codes.
    /// </summary>
    /// <remarks>
    /// This constructor takes ownership of the <paramref name="keyBlock"/> array.
    /// </remarks>
    /// <param name="keyBlock">The key block to parse</param>
    /// <exception cref="ArgumentException">Thrown when the encoded length does not match the actual length of the key block.</exception>
    public TR31KeyBlock(byte[] keyBlock)
    {
        this.keyBlock = keyBlock;
        if (this.Length != keyBlock.Length)
        {
            throw new ArgumentException($"The encoded key block length ({this.Length}) does not match the actual length of the key block ({keyBlock.Length}).", nameof(keyBlock));
        }
    }

    /// <summary>
    /// Gets the Key Block Version ID, which defines the method by which it is cryptographically protected.
    /// </summary>
    public readonly KeyBlockVersion VersionId => this.keyBlock[0] switch
    {
        (byte)'A' => KeyBlockVersion.Variant2005,
        (byte)'B' => KeyBlockVersion.Derivation2010,
        (byte)'C' => KeyBlockVersion.Variant2010,
        (byte)'D' => KeyBlockVersion.Deriviation2017,
        _ => KeyBlockVersion.Unknown,
    };

    /// <summary>
    /// Gets the key-block length, including the header, encrypted data, and MAC.
    /// </summary>
    public readonly int Length => Int32.Parse(this.keyBlock.AsSpan(1..5));

    /// <summary>
    /// Gets information about the intended function of the protected key.
    /// </summary>
    public readonly KeyUsage Usage => this.keyBlock.AsSpan(5..7) switch
    {
        [(byte)'B', (byte)'0'] => KeyUsage.BaseDerivationKey,
        [(byte)'B', (byte)'1'] => KeyUsage.InitialPinEncryptionKey,
        [(byte)'B', (byte)'3'] => KeyUsage.KeyDerivationKey,
        [(byte)'C', (byte)'0'] => KeyUsage.CardVerificationKey,
        [(byte)'D', (byte)'0'] => KeyUsage.SymmetricDataEncryptionKey,
        [(byte)'D', (byte)'3'] => KeyUsage.SensitiveDataEncryptionKey,
        [(byte)'E', (byte)'0'] => KeyUsage.EmvCryptogramKey,
        [(byte)'E', (byte)'1'] => KeyUsage.EmvConfidentialityKey,
        [(byte)'E', (byte)'2'] => KeyUsage.EmvIntegrityKey,
        [(byte)'E', (byte)'3'] => KeyUsage.EmvAuthenticationKey,
        [(byte)'E', (byte)'4'] => KeyUsage.EmvDynamicKey,
        [(byte)'E', (byte)'5'] => KeyUsage.EmvPersonalizationKey,
        [(byte)'K', (byte)'0'] => KeyUsage.KeyEncryptionKey,
        [(byte)'K', (byte)'1'] => KeyUsage.KeyBlockProtectionKeyTr31,
        [(byte)'K', (byte)'4'] => KeyUsage.KeyBlockProtectionKeyIso20038,
        [(byte)'M', (byte)'0'] => KeyUsage.Iso16609Mac1Key,
        [(byte)'M', (byte)'1'] => KeyUsage.Iso9797Mac1Key,
        [(byte)'M', (byte)'3'] => KeyUsage.Iso9797Mac3Key,
        [(byte)'M', (byte)'6'] => KeyUsage.Iso9797Mac5Key,
        [(byte)'M', (byte)'7'] => KeyUsage.HmacKey,
        [(byte)'P', (byte)'0'] => KeyUsage.PinEncryptionKey,
        [(byte)'V', (byte)'0'] => KeyUsage.PinVerificationKpvKey,
        [(byte)'V', (byte)'1'] => KeyUsage.PinVerificationIbmKey,
        [(byte)'V', (byte)'2'] => KeyUsage.PinVerificationVisaKey,
        _ => KeyUsage.Unknown,
    };

    /// <summary>
    /// Gets the approved algorithm for which the protected key may be used.
    /// </summary>
    public readonly KeyAlgorithm Algorithm => this.keyBlock[7] switch
    {
        (byte)'A' => KeyAlgorithm.AdvancedEncryptionStandard,
        (byte)'D' => KeyAlgorithm.DataEncryptionAlgorithm,
        (byte)'H' => KeyAlgorithm.HmacSha1,
        (byte)'I' => KeyAlgorithm.HmacSha2,
        (byte)'T' => KeyAlgorithm.TripleDataEncryptionAlgorithm,
        _ => KeyAlgorithm.Unknown,
    };

    /// <summary>
    /// Gets the operation the protected key can perform.
    /// </summary>
    public readonly KeyUse ModeOfUse => this.keyBlock[8] switch
    {
        (byte)'B' => KeyUse.EncryptDecrypt,
        (byte)'C' => KeyUse.GenerateVerify,
        (byte)'D' => KeyUse.Decrypt,
        (byte)'E' => KeyUse.Encrypt,
        (byte)'G' => KeyUse.Generate,
        (byte)'N' => KeyUse.NoRestriction,
        (byte)'V' => KeyUse.Verify,
        (byte)'X' => KeyUse.Derive,
        _ => KeyUse.Unknown,
    };

    /// <summary>
    /// Gets the version number of the protected key.
    /// </summary>
    public readonly int VersionNumber => Int32.Parse(this.keyBlock.AsSpan(9..11));

    /// <summary>
    /// Gets whether the key may be transferred outside the cryptographic domain.
    /// </summary>
    public readonly KeyExportability Exportability => this.keyBlock[11] switch
    {
        (byte)'E' => KeyExportability.ExtraSensitive,
        (byte)'N' => KeyExportability.NonExportable,
        (byte)'S' => KeyExportability.Sensitive,
        _ => KeyExportability.Unknown,
    };

    /// <summary>
    /// Gets the number of optional blocks included in the key block.
    /// </summary>
    public readonly int NumberOfOptionalBlocks => Int32.Parse(this.keyBlock.AsSpan(12..14));

    /// <summary>
    /// Gets whether the key is in a key exchange context or in a storage context.
    /// </summary>
    public readonly KeyContext Context => this.keyBlock[15] switch
    {
        (byte)'0' => KeyContext.StorageOrExchange,
        (byte)'1' => KeyContext.Storage,
        (byte)'2' => KeyContext.Exchange,
        _ => KeyContext.Unknown,
    };

    private readonly int HeaderLength => this.NumberOfOptionalBlocks == 0 ? 16 : throw new NotImplementedException("Optional header blocks are not yet implemented.");

    private readonly int MacLength => this.VersionId switch
    {
        KeyBlockVersion.Variant2005 => 4,
        KeyBlockVersion.Derivation2010 => 8,
        KeyBlockVersion.Variant2010 => 4,
        KeyBlockVersion.Deriviation2017 => 16,
        _ => throw new NotSupportedException($"The key block version {this.VersionId} is not supported."),
    };

    private readonly string CipherAlgorithm => this.VersionId switch
    {
        KeyBlockVersion.Derivation2010 => "DESede/CBC/NoPadding",
        KeyBlockVersion.Deriviation2017 => "AES/CBC/NoPadding",
        _ => throw new NotSupportedException($"The version ID {this.VersionId} is not supported.")
    };

    private readonly int BlockSize => this.VersionId switch
    {
        KeyBlockVersion.Derivation2010 => 8,
        KeyBlockVersion.Deriviation2017 => 16,
        _ => throw new NotSupportedException($"The version ID {this.VersionId} is not supported.")
    };

    /// <summary>
    /// Decrypts and unwraps the protected key stored within this key block.
    /// </summary>
    /// <param name="keyBlockProtectionKey">The Key Block Protection Key (KBPK) or Zone Master Key (ZMK).</param>
    /// <param name="clearKey">The decrypted and unwrapped key.</param>
    /// <returns>The number of bytes written to <paramref name="clearKey"/>.</returns>
    public readonly int Decrypt(ReadOnlySpan<byte> keyBlockProtectionKey, Span<byte> clearKey)
    {
        Span<byte> encryptionKey = stackalloc byte[keyBlockProtectionKey.Length];
        Span<byte> authenticationKey = stackalloc byte[keyBlockProtectionKey.Length];
        (int writtenEncryption, int writtenAuthentication) = DeriveKeys(keyBlockProtectionKey, encryptionKey, authenticationKey);
        encryptionKey = encryptionKey[..writtenEncryption];
        authenticationKey = authenticationKey[..writtenAuthentication];

        ReadOnlySpan<byte> header = this.keyBlock.AsSpan(..this.HeaderLength);
        ReadOnlySpan<byte> givenMacHex = this.keyBlock.AsSpan(^(this.MacLength * 2)..);
        ReadOnlySpan<byte> encryptedKeyHex = this.keyBlock.AsSpan(header.Length..^givenMacHex.Length);

        Span<byte> encryptedKey = stackalloc byte[encryptedKeyHex.Length / 2];
        OperationStatus status = Convert.FromHexString(encryptedKeyHex, encryptedKey, out int consumed, out int written);
        Debug.Assert(status == OperationStatus.Done);
        Debug.Assert(consumed == encryptedKeyHex.Length);
        Debug.Assert(written == encryptedKey.Length);

        Span<byte> givenMac = stackalloc byte[givenMacHex.Length / 2];
        status = Convert.FromHexString(givenMacHex, givenMac, out consumed, out written);
        Debug.Assert(status == OperationStatus.Done);
        Debug.Assert(consumed == givenMacHex.Length);
        Debug.Assert(written == givenMac.Length);

        ReadOnlySpan<byte> iv = this.VersionId switch
        {
            KeyBlockVersion.Variant2005 => header[..8],
            KeyBlockVersion.Derivation2010 => givenMac[..8],
            KeyBlockVersion.Variant2010 => header[..8],
            KeyBlockVersion.Deriviation2017 => givenMac[..16],
            _ => throw new NotSupportedException($"The version ID {this.VersionId} is not supported.")
        };

        Span<byte> paddedKey = stackalloc byte[encryptedKey.Length];
        written = this.DecryptKeyBlock(encryptionKey, iv, encryptedKey, paddedKey);
        paddedKey = paddedKey[..written];

        Span<byte> computedMac = stackalloc byte[givenMac.Length];
        written = this.GenerateMac(authenticationKey, header, paddedKey, computedMac);
        computedMac = computedMac[..written];
        VerifyMac(givenMac, computedMac);

        int keyLengthBits = BinaryPrimitives.ReadUInt16BigEndian(paddedKey[..2]);
        int keyLengthBytes = keyLengthBits / 8;
        paddedKey.Slice(2, keyLengthBytes).CopyTo(clearKey);
        return keyLengthBytes;
    }

    private readonly (int writtenEncryption, int writtenAuthentication) DeriveKeys(ReadOnlySpan<byte> keyBlockProtectionKey, Span<byte> encryptionKey, Span<byte> authenticationKey)
    {
        throw new NotImplementedException();
    }

    private readonly int DecryptKeyBlock(ReadOnlySpan<byte> encryptionKey, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> encryptedKey, Span<byte> paddedKey)
    {
        IBufferedCipher cipher = CipherUtilities.GetCipher(this.CipherAlgorithm);
        cipher.Init(forEncryption: false, new ParametersWithIV(new KeyParameter(encryptionKey), iv));
        return cipher.DoFinal(encryptedKey, paddedKey);
    }

    private static void VerifyMac(ReadOnlySpan<byte> givenMac, ReadOnlySpan<byte> computedMac)
    {
        if (!givenMac.SequenceEqual(computedMac))
        {
            throw new InvalidOperationException("The computed MAC does not match the encoded MAC.");
        }
    }

    private readonly int GenerateMac(ReadOnlySpan<byte> authenticationKey, ReadOnlySpan<byte> header, ReadOnlySpan<byte> paddedKey, Span<byte> computedMac)
    {
        Span<byte> data = stackalloc byte[header.Length + paddedKey.Length];
        header.CopyTo(data[..header.Length]);
        paddedKey.CopyTo(data[header.Length..]);

        IBlockCipher cipher = this.VersionId switch
        {
            KeyBlockVersion.Derivation2010 => new DesEdeEngine(),
            KeyBlockVersion.Deriviation2017 => AesUtilities.CreateEngine(),
            _ => throw new NotSupportedException($"The version ID {this.VersionId} is not supported.")
        };
        CMac cmac = new(cipher);
        cmac.Init(new KeyParameter(authenticationKey));
        cmac.BlockUpdate(data);
        return cmac.DoFinal(computedMac);
    }
}

/// <summary>
/// Identifies the version of a key block, which defines the method by which it is cryptographically protected.
/// </summary>
public enum KeyBlockVersion
{
    /// <summary>
    /// An unrecognized version
    /// </summary>
    Unknown,

    /// <summary>
    /// A: Protected by Key Variant Binding Method 2005 Edition (Deprecated)
    /// </summary>
    Variant2005,

    /// <summary>
    /// B: Protected by Key Derivation Binding Method 2010
    /// </summary>
    Derivation2010,

    /// <summary>
    /// C: Protected by Key Variant Binding Method 2010
    /// </summary>
    Variant2010,

    /// <summary>
    /// D: Protected by Key Derivation Binding Method 2017
    /// </summary>
    Deriviation2017
}

/// <summary>
/// Provides information about the intended function of a protected key.
/// </summary>
public enum KeyUsage
{
    /// <summary>
    /// An unrecognized usage
    /// </summary>
    Unknown,

    /// <summary>
    /// B0: Base Derivation Key (BDK) used to derive initial PIN encryption key (IPEK) in the derived unique key per transaction (DUKPT) process
    /// </summary>
    BaseDerivationKey,

    /// <summary>
    /// B1: Initial PIN encryption key (IPEK) in the derived unique key per transaction (DUKPT) process
    /// </summary>
    InitialPinEncryptionKey,

    /// <summary>
    /// B3: Key derivation key used as input to an irreversible key derivation function
    /// </summary>
    KeyDerivationKey,

    /// <summary>
    /// C0: Card Verification Key (CVK) for computing or verifying a card verification code
    /// </summary>
    CardVerificationKey,

    /// <summary>
    /// D0: Symmetric data encryption key
    /// </summary>
    SymmetricDataEncryptionKey,

    /// <summary>
    /// D3: Symmetric data encryption key for sensitive data
    /// </summary>
    SensitiveDataEncryptionKey,

    /// <summary>
    /// E0: Derivation key for an EMV/chip issuer master key: application cryptograms
    /// </summary>
    EmvCryptogramKey,

    /// <summary>
    /// E1: Derivation key for an EMV/chip issuer master key: secure messaging for confidentiality
    /// </summary>
    EmvConfidentialityKey,

    /// <summary>
    /// E2: Derivation key for an EMV/chip issuer master key: secure messaging for integrity
    /// </summary>
    EmvIntegrityKey,

    /// <summary>
    /// E3: Derivation key for an EMV/chip issuer master key: data authentication code
    /// </summary>
    EmvAuthenticationKey,

    /// <summary>
    /// E4: Derivation key for an EMV/chip issuer master key: dynamic numbers
    /// </summary>
    EmvDynamicKey,

    /// <summary>
    /// E5: Derivation key for an EMV/chip issuer master key: card personalization
    /// </summary>
    EmvPersonalizationKey,

    // TODO: F0-F4

    /// <summary>
    /// K0: Key encryption or wrapping key
    /// </summary>
    KeyEncryptionKey,

    /// <summary>
    /// K1: TR-31 key block protection key
    /// </summary>
    KeyBlockProtectionKeyTr31,

    /// <summary>
    /// K4: ISO 20038 key block protection key
    /// </summary>
    KeyBlockProtectionKeyIso20038,

    /// <summary>
    /// M0: ISO 16609 MAC algorithm 1 key
    /// </summary>
    Iso16609Mac1Key,

    /// <summary>
    /// M1: ISO 9797-1 MAC algorithm 1 key
    /// </summary>
    Iso9797Mac1Key,

    /// <summary>
    /// M3: ISO 9797-1 MAC algorithm 3 key
    /// </summary>
    Iso9797Mac3Key,

    /// <summary>
    /// M6: ISO 9797-1:2011 MAC algorithm 5/CMAC key
    /// </summary>
    Iso9797Mac5Key,

    /// <summary>
    /// M7: HMAC algorithm key
    /// </summary>
    HmacKey,

    /// <summary>
    /// P0: PIN encryption key
    /// </summary>
    PinEncryptionKey,

    /// <summary>
    /// V0: PIN verification, KPV, other algorithm key
    /// </summary>
    PinVerificationKpvKey,

    /// <summary>
    /// V1: PIN verification, IBM3624 key
    /// </summary>
    PinVerificationIbmKey,

    /// <summary>
    /// V2: PIN verification, Visa PVV key
    /// </summary>
    PinVerificationVisaKey,
}

/// <summary>
/// The approved algorithm for which a protected key may be used.
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>
    /// An unrecognized algorithm
    /// </summary>
    Unknown,

    /// <summary>
    /// A: Advanced Encryption Standard (AES)
    /// </summary>
    AdvancedEncryptionStandard,

    /// <summary>
    /// D: Data Encryption Algorithm (DEA)
    /// </summary>
    DataEncryptionAlgorithm,

    /// <summary>
    /// H: HMAC-SHA-1
    /// </summary>
    HmacSha1,

    /// <summary>
    /// I: HMAC-SHA-2
    /// </summary>
    HmacSha2,

    /// <summary>
    /// T: Triple Data Encryption Algorithm (TDEA)
    /// </summary>
    TripleDataEncryptionAlgorithm,
}

/// <summary>
/// Defines the operation a protected key can perform.
/// </summary>
public enum KeyUse
{
    /// <summary>
    /// An unrecognized use
    /// </summary>
    Unknown,

    /// <summary>
    /// B: Both encrypt and decrypt data, wrap and unwrap keys
    /// </summary>
    EncryptDecrypt,

    /// <summary>
    /// C: Both generate and verify of check/PIN values
    /// </summary>
    GenerateVerify,

    /// <summary>
    /// D: Decrypt data, unwrap keys only
    /// </summary>
    Decrypt,

    /// <summary>
    /// E: Encrypt data, wrap keys only
    /// </summary>
    Encrypt,

    /// <summary>
    /// G: Generate of check/PIN values only
    /// </summary>
    Generate,

    /// <summary>
    /// N: No special restrictions (other than restrictions implied by <see cref="KeyUsage"/>)
    /// </summary>
    NoRestriction,

    /// <summary>
    /// V: Verify of check/PIN values only
    /// </summary>
    Verify,

    /// <summary>
    /// X: Key used to derive other key(s)
    /// </summary>
    Derive,
}

/// <summary>
/// Defines whether a protected key may be transferred outside the cryptograhic domain in which the key is found.
/// </summary>
public enum KeyExportability
{
    /// <summary>
    /// An unknown exportability
    /// </summary>
    Unknown,

    /// <summary>
    /// E: Extra sensitive: key exportable under a key-encrypting key meeting the requirements of X9.24 Parts 1 or 2
    /// </summary>
    ExtraSensitive,

    /// <summary>
    /// N: Non-exportable
    /// </summary>
    NonExportable,

    /// <summary>
    /// S: Sensitive: key exportable under any key-encrypting key not necessarily meeting the requirements of X9.24
    /// </summary>
    Sensitive,
}

/// <summary>
/// Defines whether a key block is in a key exchange context (wrapped by a transport key) or in a storage context.
/// </summary>
public enum KeyContext
{
    /// <summary>
    /// An unrecognized context
    /// </summary>
    Unknown,

    /// <summary>
    /// 0: The key can be used in either a key storage or a key exchange context.
    /// </summary>
    StorageOrExchange,

    /// <summary>
    /// 1: The key can be used in a key storage context only.
    /// </summary>
    Storage,

    /// <summary>
    /// 2: The key can be used in a key exchange context only.
    /// </summary>
    Exchange,
}