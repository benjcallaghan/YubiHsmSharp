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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// Extensions to <see cref="YubiSession"/> to retrieve stored keys as BouncyCastle-compatible <see cref="ICipherParameters"/>.
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
        public YubiSymmetricKeyParameter GetSymmetricKeyParameter(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.SymmetricKey);
            return new YubiSymmetricKeyParameter(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored private asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored private asymmetric key.</param>
        /// <returns>A <see cref="YubiRsaKeyParameters"/> representing the stored private asymmetric key.</returns>
        public YubiRsaKeyParameters GetPrivateRsaParameters(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            return new YubiRsaKeyParameters(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiRsaKeyParameters"/> representing the public portion of the stored asymmetric key.</returns>
        public YubiRsaKeyParameters GetPublicRsaParameters(ObjectId keyId)
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
        public YubiECPrivateKeyParameters GetPrivateECParameters(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            string curveName = descriptor.Algorithm switch
            {
                Algorithm.Ecp224 => "secp224r1",
                Algorithm.Ecp256 => "secp256r1",
                Algorithm.Ecp384 => "secp384r1",
                Algorithm.Ecp521 => "secp521r1",
                Algorithm.Eck256 => "secp256k1",
                Algorithm.Ecbp256 => "brainpoolP256r1",
                Algorithm.Ecbp384 => "brainpoolP384r1",
                Algorithm.Ecbp512 => "brainpoolP512r1",
                _ => throw new NotSupportedException($"Unsupported algorithm {descriptor.Algorithm} for EC key."),
            };
            return new YubiECPrivateKeyParameters(keyId, ECDomainParameters.LookupName(curveName));
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored EC asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiECPublicKeyParameters"/> representing the public portion of the stored asymmetric key.</returns>
        public YubiECPublicKeyParameters GetPublicECParameters(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            string curveName = descriptor.Algorithm switch
            {
                Algorithm.Ecp224 => "secp224r1",
                Algorithm.Ecp256 => "secp256r1",
                Algorithm.Ecp384 => "secp384r1",
                Algorithm.Ecp521 => "secp521r1",
                Algorithm.Eck256 => "secp256k1",
                Algorithm.Ecbp256 => "brainpoolP256r1",
                Algorithm.Ecbp384 => "brainpoolP384r1",
                Algorithm.Ecbp512 => "brainpoolP512r1",
                _ => throw new NotSupportedException($"Unsupported algorithm {descriptor.Algorithm} for EC key."),
            };
            ECDomainParameters domain = ECDomainParameters.LookupName(curveName);

            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            Span<byte> x = publicKey[..(publicKey.Length / 2)];
            Span<byte> y = publicKey[(publicKey.Length / 2)..];

            ECPoint q = domain.Curve.CreatePoint(
                new BigInteger(1, x, bigEndian: true),
                new BigInteger(1, y, bigEndian: true)
            );
            return new YubiECPublicKeyParameters(keyId, q, domain);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored Ed25519 private key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiEd25519PrivateKeyParameters"/> representing the stored Ed25519 private key.</returns>
        public YubiEd25519PrivateKeyParameters GetPrivateEd25519Parameters(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);
            return new YubiEd25519PrivateKeyParameters(keyId, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing the public portion of a stored Ed25519 asymmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored asymmetric key.</param>
        /// <returns>A <see cref="YubiEd25519PublicKeyParameters"/> representing the public portion of the stored Ed25519 asymmetric key.</returns>
        public YubiEd25519PublicKeyParameters GetPublicEd25519Parameters(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.AsymmetricKey);

            Span<byte> publicKey = stackalloc byte[descriptor.Length];
            (Algorithm _, int written) = session.GetPublicKey(keyId, publicKey);
            publicKey = publicKey[..written];

            return new YubiEd25519PublicKeyParameters(keyId, publicKey);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored HMAC key.
        /// </summary>
        /// <param name="keyId">The ID of the stored HMAC key.</param>
        /// <returns>A <see cref="YubiHmacKeyParameter"/> representing the stored HMAC key.</returns>
        public YubiHmacKeyParameter GetHmacKeyParameter(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.HmacKey);
            return new YubiHmacKeyParameter(keyId, descriptor.Algorithm, descriptor.Length);
        }

        /// <summary>
        /// Gets a BouncyCastle-compatible <see cref="ICipherParameters"/> representing a stored symmetric key.
        /// </summary>
        /// <param name="keyId">The ID of the stored symmetric key.</param>
        /// <returns>A <see cref="YubiWrapKeyParameter"/> representing the stored symmetric key.</returns>
        public YubiWrapKeyParameter GetWrapKeyParameter(ObjectId keyId)
        {
            ObjectDescriptor descriptor = session.GetObject(keyId, ObjectType.WrapKey);
            return new YubiWrapKeyParameter(keyId, descriptor.Length);
        }
    }
}