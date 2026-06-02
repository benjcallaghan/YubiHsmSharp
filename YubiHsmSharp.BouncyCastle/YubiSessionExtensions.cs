using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// Extensions to <see cref="YubiSession"/> to perform PIN-related cryptographic operations.
/// </summary>
public static class YubiSessionExtensions
{
    extension(YubiSession session)
    {
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

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored private asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored private asymmetric key.</param>
        /// <returns>A <see cref="YubiRsaKeyParameters"/> representing the stored private asymmetric key.</returns>
        public YubiRsaKeyParameters GetPrivateKeyParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            return new YubiRsaKeyParameters(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiRsaKeyParameters"/> representing the public portion of the stored asymmetric key.</returns>
        public YubiRsaKeyParameters GetPublicKeyParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            
            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            BigInteger modulus = new(sign: 1, publicKey, bigEndian: true);
            BigInteger exponent = new("0x010001");

            return new YubiRsaKeyParameters(keyId, modulus, exponent);
        }
    }
}