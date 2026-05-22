using Org.BouncyCastle.Crypto;
using YubiHsmSharp.BouncyCastle;

namespace YubiHsmSharp.PciPin;

/// <summary>
/// Extensions to <see cref="YubiSession"/> to perform PIN-related cryptographic operations.
/// </summary>
public static class YubiSessionExtensions
{
    extension(YubiSession session)
    {
        /// <summary>
        /// Imports a Zone Master Key (ZMK) into YubiHSM 2 as an AES Symmetric Key.
        /// </summary>
        /// <remarks>
        /// The authentication key used to open the session requires the following capabilities: put-symmetric-key.
        /// The authentication key used to open the session requires the following delegated-capabilities:
        /// encrypt-ecb, decrypt-ecb.
        /// </remarks>
        /// <param name="utf8Label">The label of the symmetric key, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the symmetric key will be operating within.</param>
        /// <param name="zoneMasterKey">The key to import.</param>
        /// <param name="keyId">The ID of the ZMK. 0 if the ID should be assigned by the device.</param>
        /// <returns>The ID of the imported key.</returns>
        /// <exception cref="ArgumentException">Thrown if the ZMK is not a valid AES-128, AES-192, or AES-256 key.</exception>
        public ushort ImportZoneMasterKey(ReadOnlySpan<byte> utf8Label, Domains domains, ReadOnlySpan<byte> zoneMasterKey, ushort keyId = 0)
        {
            Capabilities capabilities = Capabilities.From("encrypt-ecb,decrypt-ecb"u8);
            Algorithm algorithm = zoneMasterKey.Length switch
            {
                16 => Algorithm.Aes128,
                24 => Algorithm.Aes192,
                32 => Algorithm.Aes256,
                _ => throw new ArgumentException("The provided key has an invalid length.", nameof(zoneMasterKey)),
            };
            return session.ImportAesKey(utf8Label, domains, in capabilities, algorithm, zoneMasterKey, keyId);
        }

        /// <summary>
        /// Imports an AES Symmetric Key from a <see cref="TR31KeyBlock"/>.
        /// </summary>
        /// <remarks>
        /// The authentication key used to open the session requires the following capabilities:
        /// put-symmetric-key, encrypt-ecb.
        /// The authentication key used to open the session requires the following delegated capabilities:
        /// encrypt-ecb, decrypt-ecb, exportable-under-wrap.
        /// The key block's Mode of Use and Exportability are retained as YubiHSM 2 capabilities.
        /// </remarks>
        /// <param name="keyBlock">The key block to decrypt and import.</param>
        /// <param name="zoneMasterKeyId">The ID of the symmetric Zone Master Key (ZMK).</param>
        /// <param name="utf8Label">The label of the symmetrtic key, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the symmetric key will be operating within.</param>
        /// <param name="keyId">The ID of the imported key. 0 if the ID should be assigned by the device.</param>
        /// <returns>The ID of the imported key.</returns>
        /// <exception cref="ArgumentException">Thrown if the imported key is not a valid AES-128, AES-192, or AES-256 key,
        /// or if the key block has an unsupported Mode of Use, or if the key block has an unsupported Exporatability.</exception>
        public ushort ImportAesKey(TR31KeyBlock keyBlock, ushort zoneMasterKeyId, ReadOnlySpan<byte> utf8Label,
            Domains domains, ushort keyId = 0)
        {
            if (keyBlock.Algorithm != KeyAlgorithm.AdvancedEncryptionStandard)
            {
                throw new ArgumentException("Only AES keys are supported.", nameof(keyBlock));
            }

            Capabilities modeOfUse = Capabilities.From(keyBlock.ModeOfUse switch
            {
                KeyUse.NoRestriction => "encrypt-ecb,decrypt-ecb"u8,
                KeyUse.EncryptDecrypt => "encrypt-ecb,decrypt-ecb"u8,
                KeyUse.Encrypt => "encrypt-ecb"u8,
                KeyUse.Decrypt => "decrypt-ecb"u8,
                _ => throw new ArgumentException($"The key use '{keyBlock.ModeOfUse}' is not supported.", nameof(keyBlock))
            });
            Capabilities exportability = keyBlock.Exportability switch
            {
                // Assuming the caller has a wrap key that is "extra sensitive" compatible.
                KeyExportability.ExtraSensitive => Capabilities.From("exportable-under-wrap"u8),
                KeyExportability.NonExportable => new Capabilities(),
                KeyExportability.Sensitive => Capabilities.From("exportable-under-wrap"u8),
                _ => throw new ArgumentException($"The exportablity '{keyBlock.Exportability}' is not supported.", nameof(keyBlock)),
            };
            Capabilities capabilities = modeOfUse.Merge(in exportability);

            YubiSymmetricKeyParameter keyParameter = session.GetSymmetricKeyParameter(zoneMasterKeyId);

            Span<byte> clearKey = stackalloc byte[keyParameter.KeyLength];
            int written = keyBlock.Decrypt(new YubiAesBlockCipher(session), keyParameter, clearKey);
            clearKey = clearKey[..written];

            Algorithm algorithm = clearKey.Length switch
            {
                16 => Algorithm.Aes128,
                24 => Algorithm.Aes192,
                32 => Algorithm.Aes256,
                _ => throw new ArgumentException("The provided key has an invalid length.", nameof(keyBlock)),
            };
            return session.ImportAesKey(utf8Label, domains, in capabilities, algorithm, clearKey, keyId);
        }

        /// <summary>
        /// Encrypts a PIN into a Format 4 PIN Block using a stored symmetric key.
        /// </summary>
        /// <remarks>
        /// The authentication key used to create the session must have the following capabilities:
        /// encrypt-ecb, get-pseudo-random
        /// </remarks>
        /// <param name="pinEncryptionKeyId">The ID of the stored symmetric key.</param>
        /// <param name="pin">The PIN to encipher.</param>
        /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
        /// <returns>A Format 4 PIN Block containing the enciphered PIN.</returns>
        public Format4PinBlock EncryptPin(ushort pinEncryptionKeyId, string pin, string primaryAccountNumber)
        {
            YubiSymmetricKeyParameter keyParameter = session.GetSymmetricKeyParameter(pinEncryptionKeyId);
            return Format4PinBlock.Encrypt(
                new YubiAesBlockCipher(session),
                keyParameter,
                new YubiRandomGenerator(session),
                pin,
                primaryAccountNumber);
        }

        /// <summary>
        /// Decrypts a PIN from a Format 4 PIN Block using a stored symmetric key.
        /// </summary>
        /// <remarks>
        /// The authentication key used to create the session must have the following capabilities:
        /// decrypt-ecb
        /// </remarks>
        /// <param name="pinEncryptionKeyId">The ID of the stored symmetric key.</param>
        /// <param name="pinBlock">The PIN Block to decipher.</param>
        /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
        /// <returns>The deciphered PIN.</returns>
        public string DecryptPin(ushort pinEncryptionKeyId, Format4PinBlock pinBlock, string primaryAccountNumber)
        {
            YubiSymmetricKeyParameter keyParameter = session.GetSymmetricKeyParameter(pinEncryptionKeyId);
            return pinBlock.Decrypt(new YubiAesBlockCipher(session), keyParameter, primaryAccountNumber);
        }
    }
}