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
/// Algorithms
/// </summary>
/// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithm.html"/>
public enum Algorithm
{
    /// <summary>rsa-pkcs1-sha1</summary>
    RsaPkcs1Sha1 = 1,

    /// <summary>rsa-pkcs1-sha256</summary>
    RsaPkcs1Sha256 = 2,

    /// <summary>rsa-pkcs1-sha384</summary>
    RsaPkcs1Sha384 = 3,

    /// <summary>rsa-pkcs1-sha512</summary>
    RsaPkcs1Sha512 = 4,

    /// <summary>rsa-pss-sha1</summary>
    RsaPssSha1 = 5,

    /// <summary>rsa-pss-sha256</summary>
    RsaPssSha256 = 6,

    /// <summary>rsa-pss-sha384</summary>
    RsaPssSha384 = 7,

    /// <summary>rsa-pss-sha512</summary>
    RsaPssSha512 = 8,

    /// <summary>rsa2048</summary>
    Rsa2048 = 9,

    /// <summary>rsa3072</summary>
    Rsa3072 = 10,

    /// <summary>rsa4096</summary>
    Rsa4096 = 11,

    /// <summary>ecp256</summary>
    Ecp256 = 12,

    /// <summary>ecp384</summary>
    Ecp384 = 13,

    /// <summary>ecp521</summary>
    Ecp521 = 14,

    /// <summary>eck256</summary>
    Eck256 = 15,

    /// <summary>ecbp256</summary>
    Ecbp256 = 16,

    /// <summary>ecbp384</summary>
    Ecbp384 = 17,

    /// <summary>ecbp512</summary>
    Ecbp512 = 18,

    /// <summary>hmac-sha1</summary>
    HmacSha1 = 19,

    /// <summary>hmac-sha256</summary>
    HmacSha256 = 20,

    /// <summary>hmac-sha384</summary>
    HmacSha384 = 21,

    /// <summary>hmac-sha512</summary>
    HmacSha512 = 22,

    /// <summary>ecdsa-sha1</summary>
    EcdsaSha1 = 23,

    /// <summary>ecdh</summary>
    Ecdh = 24,

    /// <summary>rsa-oaep-sha1</summary>
    RsaOaepSha1 = 25,

    /// <summary>rsa-oaep-sha256</summary>
    RsaOaepSha256 = 26,

    /// <summary>rsa-oaep-sha384</summary>
    RsaOaepSha384 = 27,

    /// <summary>rsa-oaep-sha512</summary>
    RsaOaepSha512 = 28,

    /// <summary>aes128-ccm-wrap</summary>
    Aes128CcmWrap = 29,

    /// <summary>opaque-data</summary>
    OpaqueData = 30,

    /// <summary>opaque-x509-certificate</summary>
    OpaqueX509Certificate = 31,

    /// <summary>mgf1-sha1</summary>
    Mgf1Sha1 = 32,

    /// <summary>mgf1-sha256</summary>
    Mgf1Sha256 = 33,

    /// <summary>mgf1-sha384</summary>
    Mgf1Sha384 = 34,

    /// <summary>mgf1-sha512</summary>
    Mgf1Sha512 = 35,

    /// <summary>template-ssh</summary>
    TemplateSsh = 36,

    /// <summary>aes128-yubico-otp</summary>
    Aes128YubicoOtp = 37,

    /// <summary>aes128-yubico-authentication</summary>
    Aes128YubicoAuthentication = 38,

    /// <summary>aes192-yubico-otp</summary>
    Aes192YubicoOtp = 39,

    /// <summary>aes256-yubico-otp</summary>
    Aes256YubicoOtp = 40,

    /// <summary>aes192-ccm-wrap</summary>
    Aes192CcmWrap = 41,

    /// <summary>aes256-ccm-wrap</summary>
    Aes256CcmWrap = 42,

    /// <summary>ecdsa-sha256</summary>
    EcdsaSha256 = 43,

    /// <summary>ecdsa-sha384</summary>
    EcdsaSha384 = 44,

    /// <summary>ecdsa-sha512</summary>
    EcdsaSha512 = 45,

    /// <summary>ed25519</summary>
    Ed25519 = 46,

    /// <summary>ecp224</summary>
    Ecp224 = 47,

    /// <summary>rsa-pkcs1-decrypt</summary>
    RsaPkcs1Decrypt = 48,

    /// <summary>ec-p256-yubico-authentication</summary>
    ECP256YubicoAuthentication = 49,

    /// <summary>aes128</summary>
    Aes128 = 50,

    /// <summary>aes192</summary>
    Aes192 = 51,

    /// <summary>aes256</summary>
    Aes256 = 52,

    /// <summary>aes-ecb</summary>
    AesEcb = 53,

    /// <summary>aes-cbc</summary>
    AesCbc = 54,

    /// <summary>aes-kwp</summary>
    AesKwp = 55,
}
