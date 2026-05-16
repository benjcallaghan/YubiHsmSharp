/*
 * Copyright 2015-2018 Yubico AB
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

namespace YubiHsmSharp;

/// <summary>
/// Object types
/// </summary>
/// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html"/>
public enum ObjectType
{
    /// <summary>Opaque Object is an unchecked kind of Object, normally used to store
    /// raw data in the device</summary>
    Opaque = 0x01,

    /// <summary>Authentication Key is used to establish Sessions with a device</summary>
    AuthenticationKey = 0x02,

    /// <summary>Asymmetric Key is the private key of an asymmetric key-pair</summary>
    AsymmetricKey = 0x03,

    /// <summary>Wrap Key is a secret key used to wrap and unwrap Objects during the
    /// export and import process</summary>
    WrapKey = 0x04,

    /// <summary>HMAC Key is a secret key used when computing and verifying HMAC signatures</summary>
    HmacKey = 0x05,

    /// <summary>Template is a binary object used for example to validate SSH certificate
    /// requests</summary>
    Template = 0x06,

    /// <summary>OTP AEAD Key is a secret key used to decrypt Yubico OTP values</summary>
    OtpAeadKey = 0x07,

    /// <summary>Symmetric Key is a secret key used for encryption and decryption.</summary>
    SymmetricKey = 0x08,

    /// <summary>Public Wrap Key is a public key used to wrap Objects during the
    /// export process</summary>
    PublicWrapKey = 0x09,

    /// <summary>Public Key is the public key of an asymmetric key-pair. The public key
    /// never exists in device and is mostly here for PKCS#11.</summary>
    PublicKey = AsymmetricKey | 0x80,

    /// <summary>Wrap Key public is the public key of an asymmetric wrap key. The public key
    /// never exists in device and is mostly here for PKCS#11.</summary>
    WrapKeyPublic = WrapKey | 0x80,
}

/// <summary>
/// A set of extension methods for <see cref="ObjectType"/>.
/// </summary>
public static class ObjectTypeExtensions
{
    extension(ObjectType type)
    {
        /// <summary>
        /// Converts the object type to its string representation.
        /// </summary>
        /// <returns>The string representation of the type.</returns>
        public string ToYubiString()
        {
            yh_rc err = yh_type_to_string(type, out nint result);
            YubiHsmException.ThrowIfError(err);
            return Marshal.PtrToStringUTF8(result) ?? String.Empty;
        }

        /// <summary>
        /// Converts a string to a type's numeric value.
        /// </summary>
        /// <param name="utf8String">Type as a string, UTF-8 encoded and null-terminated.</param>
        /// <returns>The numeric value of the object type.</returns>
        public static ObjectType From(ReadOnlySpan<byte> utf8String)
        {
            yh_rc err = yh_string_to_type(utf8String, out ObjectType result);
            YubiHsmException.ThrowIfError(err);
            return result;
        }
    }
}