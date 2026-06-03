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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.X509;

namespace YubiHsmSharp.Examples;

public class Attestation
{
    [Fact]
    public void Main()
    {
        using YubiModule module = new();
        using YubiConnector connector = module.InitConnector("http://localhost:12345"u8);
        connector.Connect();

        ushort authKeyId = 1;
        using YubiSession session = connector.CreateSession(authKeyId, "password"u8);
        byte sessionId = session.SessionId;

        ReadOnlySpan<byte> keyLabel = "label"u8;
        Capabilities capabilities = Capabilities.From("sign-attestation-certificate"u8);
        Domains domainFive = Domains.From("5"u8);
        ushort attestingKeyId = session.GenerateECKey(keyLabel, domainFive, in capabilities, Algorithm.Ecp256);

        Span<byte> publicKey = stackalloc byte[256];
        (Algorithm algo, int written) = session.GetPublicKey(attestingKeyId, publicKey[1..]);
        publicKey = publicKey[..(written + 1)];
        publicKey[0] = 0x04;

        string curveName = algo switch
        {
            Algorithm.Ecp256 => "prime256v1",
            Algorithm.ECP256YubicoAuthentication => "prime256v1",
            Algorithm.Ecp384 => "secp384r1",
            Algorithm.Ecp521 => "secp521r1",
            Algorithm.Ecp224 => "secp224r1",
            Algorithm.Eck256 => "secp256k1",
            Algorithm.Ecbp256 => "brainpoolP256r1",
            Algorithm.Ecbp384 => "brainpoolP384r1",
            Algorithm.Ecbp512 => "brainpoolP512r1",
            Algorithm.Ed25519 => "ED25519",
            _ => ""
        };
        Assert.NotEmpty(curveName);

        ECDomainParameters domain = ECDomainParameters.LookupName(curveName);
        ECPoint point = domain.Curve.DecodePoint(publicKey);
        ECPublicKeyParameters attestingKeyPublic = new(point, domain);

        byte[] attestationTemplatePem = """
            -----BEGIN CERTIFICATE-----
            MIIC8TCCAdmgAwIBAgIJAI4siOgx84SNMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV
            BAMMBHRlc3QwHhcNMTcwMzE3MTMwODAyWhcNMjcwMzE1MTMwODAyWjAPMQ0wCwYD
            VQQDDAR0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0J9YugQ
            3po8PtkrhQsq4aUbU0y2MtruYvZjRG0tMMtTrE92FXqrBltL+LXjhC6nOcgkjb4U
            JFdJzK+QsQ3jpJNOpGWSWHCrEk8CVJnl2klq6vhlcSTlojHu912WYdiCudA0KhQ+
            ffFhfGpAItctLMvaD7aS01l/OKzXAUkCv+8f2p+/+2I7mEnv88gOsisf78kqRPrQ
            b1xuRvHdNsehtxo+VN5bbKICkNskd18EloX46LjYi9oQ0zihmm24yGYPWUmDv1zm
            CBlM2AT2kHxHtHMl+DyewZERYtHKUN3irzyEq/9H2TxsfsYk2wR8QtAADU+mMe9M
            ne9lXrkgusx4RQIDAQABo1AwTjAdBgNVHQ4EFgQUGzIsrm1ZNd37V7vCLXolfTtM
            xEEwHwYDVR0jBBgwFoAUGzIsrm1ZNd37V7vCLXolfTtMxEEwDAYDVR0TBAUwAwEB
            /zANBgkqhkiG9w0BAQsFAAOCAQEAh7S+9c8Mcg/aK6qhQ/m0WJUSW5W4QL0p3fwG
            ettK+4tntI6ufgaJgxgvG8ucrcOJ/j/s7ZDqJ7MjRsZm391616oZixkPzCrBhWgr
            3Vv6gFtnxXrwQMdgvzpKhtSrxjoDyUnFLs14H/e/L0+qGAlAN2adHHha7zouaWwY
            +KyyK5sX2m/yQg/uQm4KeVqz3wsA6zJXIg0EEH/ISj7JBCCyux3ouS3x/z+43Hl4
            DzFJtJotn34HKe02gcCd4qxginQJJ84j2G4JZ42deVFPPp6dbHIuLFHunCH8HTkA
            jpI5R8+6LS+5+gci9J5OaVMAgvy6cYqx85lbaoyXdXB8aGLkNw==
            -----END CERTIFICATE-----
            """u8.ToArray();
        X509CertificateParser parser = new();
        X509Certificate attestationTemplate = parser.ReadCertificate(attestationTemplatePem);
        byte[] attestationTemplateDer = attestationTemplate.GetEncoded();

        capabilities = default;
        attestingKeyId = session.ImportOpaque(keyLabel, domainFive, capabilities, Algorithm.OpaqueX509Certificate,
            attestationTemplateDer, attestingKeyId);

        Span<byte> buffer = stackalloc byte[3072];
        written = session.GetOpaque(attestingKeyId, buffer);
        buffer = buffer[..written];
        Assert.Equal(attestationTemplateDer, buffer);

        capabilities = Capabilities.From("sign-ecdsa"u8);
        ushort attestedKeyId = session.GenerateECKey(keyLabel, domainFive, capabilities, Algorithm.Ecp256);

        Span<byte> attestation = stackalloc byte[2048];
        written = session.SignAttestationCertificate(attestedKeyId, attestingKeyId, attestation);
        X509Certificate x509 = new(attestation[..written].ToArray());
        Assert.True(x509.CertificateStructure.Extensions.Count >= 6);
        x509.Verify(attestingKeyPublic);

        written = session.SignAttestationCertificate(attestingKeyId, attestingKeyId, attestation);
        x509 = new(attestation[..written].ToArray());
        Assert.True(x509.CertificateStructure.Extensions.Count >= 6);
        x509.Verify(attestingKeyPublic);

        written = session.SignAttestationCertificate(0, attestingKeyId, attestation);
        x509 = new(attestation[..written].ToArray());
        Assert.True(x509.CertificateStructure.Extensions.Count >= 6);
        x509.Verify(attestingKeyPublic);
    }
}