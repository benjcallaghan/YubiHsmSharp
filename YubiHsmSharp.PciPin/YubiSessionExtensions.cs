using Org.BouncyCastle.Crypto;

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
        /// <param name="utf8Label">The label of the opaque object, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the opaque object will be operating within.</param>
        /// <param name="zoneMasterKey">The key to import.</param>
        /// <param name="keyId">The ID of the ZMK. 0 if the ID should be assigned by the device.</param>
        /// <returns>The ID of the imported key.</returns>
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
            return session.ImportAesKey(utf8Label, domains, capabilities, algorithm, zoneMasterKey, keyId);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored symmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored symmetric key.</param>
        /// <returns>A <see cref="YubiSymmetricKeyParameter"/> representing the stored symmetric key.</returns>
        public YubiSymmetricKeyParameter GetSymmetricKeyParameter(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.SymmetricKey);
            return new YubiSymmetricKeyParameter(keyId, descriptor.Length);
        }
    }
}