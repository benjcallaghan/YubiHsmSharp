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
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

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
        public ObjectId ImportZoneMasterAesKey(ReadOnlySpan<byte> utf8Label, Domains domains, ReadOnlySpan<byte> zoneMasterKey, ObjectId keyId = default)
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
        /// Imports a Zone Master Key (ZMK) into YubiHSM 2 as an Opaque Object.
        /// </summary>
        /// <remarks>
        /// The authentication key used to open the session requires the following capabilities: put-opaque.
        /// The authentication key used to open the session requires the following delegated-capabilities:
        /// encrypt-ecb, decrypt-ecb.
        /// </remarks>
        /// <param name="utf8Label">The label of the symmetric key, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the symmetric key will be operating within.</param>
        /// <param name="zoneMasterKey">The key to import.</param>
        /// <param name="keyId">The ID of the ZMK. 0 if the ID should be assigned by the device.</param>
        /// <returns>The ID of the imported key.</returns>
        public ObjectId ImportZoneMasterDesKey(ReadOnlySpan<byte> utf8Label, Domains domains, ReadOnlySpan<byte> zoneMasterKey, ObjectId keyId = default)
        {
            Capabilities capabilities = Capabilities.From("encrypt-ecb,decrypt-ecb"u8);
            return session.ImportOpaque(utf8Label, domains, in capabilities, Algorithm.OpaqueData, zoneMasterKey, keyId);
        }

        /// <summary>
        /// Imports a Symmetric Key from a <see cref="TR31KeyBlock"/>.
        /// </summary>
        /// <remarks>
        /// The authentication key used to open the session requires the following capabilities:
        /// put-symmetric-key, put-mac-key, put-opaque, put-wrap-key, encrypt-ecb, get-opaque.
        /// The authentication key used to open the session requires the following delegated capabilities:
        /// encrypt-ecb, decrypt-ecb, sign-hmac, verify-hmac, export-wrapped, import-wrapped,
        /// wrap-data, unwrap-data, exportable-under-wrap.
        /// The key block's Mode of Use and Exportability are retained as YubiHSM 2 capabilities.
        /// </remarks>
        /// <param name="keyBlock">The key block to decrypt and import.</param>
        /// <param name="zoneMasterKeyId">The ID of the symmetric Zone Master Key (ZMK).</param>
        /// <param name="utf8Label">The label of the symmetrtic key, UTF-8 encoded and null-terminated.</param>
        /// <param name="domains">The domains where the symmetric key will be operating within.</param>
        /// <param name="keyId">The ID of the imported key. 0 if the ID should be assigned by the device.</param>
        /// <returns>A tuple containing the <see cref="ObjectType"/> and <see cref="ObjectId"/> of the imported key.</returns>
        /// <exception cref="ArgumentException">Thrown if the key block cannot be mapped to YubiHSM 2 metadata.</exception>
        public (ObjectType, ObjectId) ImportKeyBlock(TR31KeyBlock keyBlock, ObjectId zoneMasterKeyId, ReadOnlySpan<byte> utf8Label,
            Domains domains, ObjectId keyId = default)
        {
            ObjectType objectType = (keyBlock.Algorithm, keyBlock.Usage) switch
            {
                (KeyAlgorithm.AdvancedEncryptionStandard, KeyUsage.KeyEncryptionKey
                or KeyUsage.SensitiveDataEncryptionKey or KeyUsage.SymmetricDataEncryptionKey
                or KeyUsage.KeyBlockProtectionKeyTr31 or KeyUsage.KeyBlockProtectionKeyIso20038)
                    => ObjectType.WrapKey,
                (KeyAlgorithm.AdvancedEncryptionStandard, _) => ObjectType.SymmetricKey,
                (KeyAlgorithm.DataEncryptionAlgorithm, _) => ObjectType.Opaque,
                (KeyAlgorithm.TripleDataEncryptionAlgorithm, _) => ObjectType.Opaque,
                (KeyAlgorithm.HmacSha1, _) => ObjectType.HmacKey,
                (KeyAlgorithm.HmacSha2, _) => ObjectType.HmacKey,
                _ => throw new NotSupportedException($"The mode of use '{keyBlock.Algorithm}' is not supported."),
            };
            Capabilities modeOfUse = (keyBlock.ModeOfUse, keyBlock.Usage) switch
            {
                (KeyUse.EncryptDecrypt, _) => Capabilities.From("encrypt-ecb,decrypt-ecb"u8),
                (KeyUse.Encrypt, _) => Capabilities.From("encrypt-ecb"u8),
                (KeyUse.Decrypt, _) => Capabilities.From("decrypt-ecb"u8),
                (KeyUse.GenerateVerify, _) => Capabilities.From("sign-hmac,verify-hmac"u8),
                (KeyUse.Generate, _) => Capabilities.From("sign-hmac"u8),
                (KeyUse.Verify, _) => Capabilities.From("verify-hmac"u8),
                (KeyUse.NoRestriction, KeyUsage.KeyEncryptionKey
                or KeyUsage.KeyBlockProtectionKeyTr31 or KeyUsage.KeyBlockProtectionKeyIso20038)
                    => Capabilities.From("export-wrapped,import-wrapped"u8),
                (KeyUse.NoRestriction, KeyUsage.PinEncryptionKey)
                    => Capabilities.From("encrypt-ecb,decrypt-ecb"u8),
                (KeyUse.NoRestriction, KeyUsage.HmacKey or KeyUsage.Iso16609Mac1Key
                or KeyUsage.Iso9797Mac1Key or KeyUsage.Iso9797Mac3Key or KeyUsage.Iso9797Mac5Key)
                    => Capabilities.From("sign-hmac,verify-hmac"u8),
                (KeyUse.NoRestriction, KeyUsage.SensitiveDataEncryptionKey or KeyUsage.SymmetricDataEncryptionKey)
                    => Capabilities.From("wrap-data,unwrap-data"u8),
                _ => throw new NotSupportedException($"The mode of use '{keyBlock.ModeOfUse}' is not supported."),
            };
            Capabilities exportability = keyBlock.Exportability switch
            {
                // Assuming the caller has a wrap key that is "extra sensitive" compatible.
                KeyExportability.ExtraSensitive => Capabilities.From("exportable-under-wrap"u8),
                KeyExportability.NonExportable => default,
                KeyExportability.Sensitive => Capabilities.From("exportable-under-wrap"u8),
                _ => throw new ArgumentException($"The exportablity '{keyBlock.Exportability}' is not supported.", nameof(keyBlock)),
            };
            Capabilities capabilities = modeOfUse.Merge(in exportability);
            Capabilities delegated = Capabilities.From("encrypt-ecb,decrypt-ecb,sign-hmac,verify-hmac,export-wrapped,import-wrapped,wrap-data,unwrap-data,exportable-under-wrap"u8);
            KeyParameter keyParameter = keyBlock.VersionId switch
            {
                KeyBlockVersion.Derivation2017 => session.GetSymmetricKeyParameter(zoneMasterKeyId),
                _ => session.GetOpaqueKeyParameter(zoneMasterKeyId),
            };
            IBlockCipher cipher = keyBlock.VersionId switch
            {
                KeyBlockVersion.Derivation2017 => new YubiAes(session),
                _ => new DesEdeEngine(),
            };

            Span<byte> clearKey = stackalloc byte[keyParameter.KeyLength];
            int written = keyBlock.Decrypt(cipher, keyParameter, clearKey);
            clearKey = clearKey[..written];

            Algorithm algorithm = (objectType, clearKey.Length) switch
            {
                (ObjectType.Opaque, _) => Algorithm.OpaqueData,
                (ObjectType.SymmetricKey, 16) => Algorithm.Aes128,
                (ObjectType.SymmetricKey, 24) => Algorithm.Aes192,
                (ObjectType.SymmetricKey, 32) => Algorithm.Aes256,
                (ObjectType.HmacKey, 20) => Algorithm.HmacSha1,
                (ObjectType.HmacKey, 32) => Algorithm.HmacSha256,
                (ObjectType.HmacKey, 48) => Algorithm.HmacSha384,
                (ObjectType.HmacKey, 64) => Algorithm.HmacSha512,
                (ObjectType.WrapKey, 16) => Algorithm.Aes128CcmWrap,
                (ObjectType.WrapKey, 24) => Algorithm.Aes192CcmWrap,
                (ObjectType.WrapKey, 32) => Algorithm.Aes256CcmWrap,
                _ => throw new NotSupportedException($"The key length '{clearKey.Length}' is not supported."),
            };
            ObjectId objectId = objectType switch
            {
                ObjectType.SymmetricKey => session.ImportAesKey(utf8Label, domains, in capabilities, algorithm, clearKey, keyId),
                ObjectType.Opaque => session.ImportOpaque(utf8Label, domains, in capabilities, algorithm, clearKey, keyId),
                ObjectType.HmacKey => session.ImportHmacKey(utf8Label, domains, in capabilities, algorithm, clearKey, keyId),
                ObjectType.WrapKey => session.ImportWrapKey(utf8Label, domains, in capabilities, algorithm, in delegated, clearKey, keyId),
                _ => throw new NotSupportedException($"The object type '{objectType}' is not supported."),
            };

            return (objectType, objectId);
        }

        /// <summary>
        /// Encrypts a PIN into a Format 4 PIN Block using a stored symmetric key.
        /// </summary>
        /// <remarks>
        /// The authentication key used to create the session must have the following capabilities:
        /// encrypt-ecb, get-opaque, get-pseudo-random
        /// </remarks>
        /// <param name="pinEncryptionKeyType">The type of the stored symmetric key.</param>
        /// <param name="pinEncryptionKeyId">The ID of the stored symmetric key.</param>
        /// <param name="pin">The PIN to encipher.</param>
        /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
        /// <returns>A Format 4 PIN Block containing the enciphered PIN.</returns>
        public Format4PinBlock EncryptPin(ObjectType pinEncryptionKeyType, ObjectId pinEncryptionKeyId,
            string pin, string primaryAccountNumber)
        {
            KeyParameter keyParameter = pinEncryptionKeyType switch
            {
                ObjectType.SymmetricKey => session.GetSymmetricKeyParameter(pinEncryptionKeyId),
                ObjectType.Opaque => session.GetOpaqueKeyParameter(pinEncryptionKeyId),
                _ => throw new NotSupportedException($"The object type '{pinEncryptionKeyType}' is not supported."),
            };
            IBlockCipher cipher = pinEncryptionKeyType switch
            {
                ObjectType.SymmetricKey => new YubiAes(session),
                ObjectType.Opaque => new DesEdeEngine(),
                _ => throw new NotSupportedException($"The object type '{pinEncryptionKeyType}' is not supported."),
            };

            return Format4PinBlock.Encrypt(
                cipher,
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
        /// decrypt-ecb, get-opaque
        /// </remarks>
        /// <param name="pinEncryptionKeyType">The type of the stored symmetric key.</param>
        /// <param name="pinEncryptionKeyId">The ID of the stored symmetric key.</param>
        /// <param name="pinBlock">The PIN Block to decipher.</param>
        /// <param name="primaryAccountNumber">The Primary Account Number (PAN) associated with the PIN.</param>
        /// <returns>The deciphered PIN.</returns>
        public string DecryptPin(ObjectType pinEncryptionKeyType, ObjectId pinEncryptionKeyId,
            Format4PinBlock pinBlock, string primaryAccountNumber)
        {
            KeyParameter keyParameter = pinEncryptionKeyType switch
            {
                ObjectType.SymmetricKey => session.GetSymmetricKeyParameter(pinEncryptionKeyId),
                ObjectType.Opaque => session.GetOpaqueKeyParameter(pinEncryptionKeyId),
                _ => throw new NotSupportedException($"The object type '{pinEncryptionKeyType}' is not supported."),
            };
            IBlockCipher cipher = pinEncryptionKeyType switch
            {
                ObjectType.SymmetricKey => new YubiAes(session),
                ObjectType.Opaque => new DesEdeEngine(),
                _ => throw new NotSupportedException($"The object type '{pinEncryptionKeyType}' is not supported."),
            };

            return pinBlock.Decrypt(cipher, keyParameter, primaryAccountNumber);
        }
    }
}