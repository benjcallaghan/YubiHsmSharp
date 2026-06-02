using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

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
        public YubiRsaKeyParameters GetPrivateRsaParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            return new YubiRsaKeyParameters(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiRsaKeyParameters"/> representing the public portion of the stored asymmetric key.</returns>
        public YubiRsaKeyParameters GetPublicRsaParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);

            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            BigInteger modulus = new(sign: 1, publicKey, bigEndian: true);
            BigInteger exponent = new("0x010001");

            return new YubiRsaKeyParameters(keyId, modulus, exponent);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored EC private key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiECPrivateKeyParameters"/> representing the stored EC private key.</returns>
        public YubiECPrivateKeyParameters GetPrivateECParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            X9ECParameters parameters = descriptor.Algorithm switch
            {
                Algorithm.Ecp224 => ECNamedCurveTable.GetByName("secp224r1"),
                Algorithm.Ecp256 => ECNamedCurveTable.GetByName("secp256r1"),
                Algorithm.Ecp384 => ECNamedCurveTable.GetByName("secp384r1"),
                Algorithm.Ecp521 => ECNamedCurveTable.GetByName("secp521r1"),
                Algorithm.Eck256 => ECNamedCurveTable.GetByName("secp256k1"),
                Algorithm.Ecbp256 => ECNamedCurveTable.GetByName("brainpoolP256r1"),
                Algorithm.Ecbp384 => ECNamedCurveTable.GetByName("brainpoolP384r1"),
                Algorithm.Ecbp512 => ECNamedCurveTable.GetByName("brainpoolP512r1"),
                _ => throw new NotSupportedException($"Unsupported algorithm {descriptor.Algorithm} for EC key."),
            };
            return new YubiECPrivateKeyParameters(keyId, ECDomainParameters.FromX9ECParameters(parameters));
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored EC asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiECPublicKeyParameters"/> representing the public portion of the stored asymmetric key.</returns>
        public YubiECPublicKeyParameters GetPublicECParameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            X9ECParameters parameters = descriptor.Algorithm switch
            {
                Algorithm.Ecp224 => ECNamedCurveTable.GetByName("secp224r1"),
                Algorithm.Ecp256 => ECNamedCurveTable.GetByName("secp256r1"),
                Algorithm.Ecp384 => ECNamedCurveTable.GetByName("secp384r1"),
                Algorithm.Ecp521 => ECNamedCurveTable.GetByName("secp521r1"),
                Algorithm.Eck256 => ECNamedCurveTable.GetByName("secp256k1"),
                Algorithm.Ecbp256 => ECNamedCurveTable.GetByName("brainpoolP256r1"),
                Algorithm.Ecbp384 => ECNamedCurveTable.GetByName("brainpoolP384r1"),
                Algorithm.Ecbp512 => ECNamedCurveTable.GetByName("brainpoolP512r1"),
                _ => throw new NotSupportedException($"Unsupported algorithm {descriptor.Algorithm} for EC key."),
            };

            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            Span<byte> x = publicKey[..(publicKey.Length / 2)];
            Span<byte> y = publicKey[(publicKey.Length / 2)..];

            ECPoint q = parameters.Curve.CreatePoint(
                new BigInteger(1, x, bigEndian: true),
                new BigInteger(1, y, bigEndian: true)
            );
            return new YubiECPublicKeyParameters(keyId, q, ECDomainParameters.FromX9ECParameters(parameters));
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored Ed25519 private key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiEd25519PrivateKeyParameters"/> representing the stored Ed25519 private key.</returns>
        public YubiEd25519PrivateKeyParameters GetPrivateEd25519Parameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            return new YubiEd25519PrivateKeyParameters(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored Ed25519 asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiEd25519PublicKeyParameters"/> representing the public portion of the stored Ed25519 asymmetric key.</returns>
        public YubiEd25519PublicKeyParameters GetPublicEd25519Parameters(ushort keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);

            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            return new YubiEd25519PublicKeyParameters(keyId, publicKey);
        }
    }
}