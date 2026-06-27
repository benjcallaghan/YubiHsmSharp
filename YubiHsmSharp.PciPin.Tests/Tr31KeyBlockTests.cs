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
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.PciPin.Tests;

[Trait("Requires", "None")]
public class TR31KeyBlockTests
{
    [Theory]
    [InlineData(KeyBlockVersion.Variant2005)]
    [InlineData(KeyBlockVersion.Derivation2010)]
    [InlineData(KeyBlockVersion.Variant2010)]
    [InlineData(KeyBlockVersion.Derivation2017)]
    public void TR31KeyBlock_WhenEncrypted_DecryptsToOriginalData(KeyBlockVersion versionId)
    {
        // Arrange
        CipherKeyGenerator generator = new();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 128));
        KeyParameter protectionKey = generator.GenerateKeyParameter();
        KeyParameter encryptionKey = generator.GenerateKeyParameter();
        CryptoApiRandomGenerator random = new();

        TR31KeyBlock keyBlock = new()
        {
            VersionId = versionId,
            Usage = KeyUsage.PinEncryptionKey,
            Algorithm = KeyAlgorithm.AdvancedEncryptionStandard,
            ModeOfUse = KeyUse.EncryptDecrypt,
            VersionNumber = 1,
            Exportability = KeyExportability.Sensitive,
            Context = KeyContext.StorageOrExchange
        };

        // Act
        keyBlock.Encrypt(protectionKey.GetKey(), random, encryptionKey.GetKey());
        TR31KeyBlock cloned = new(keyBlock.Raw.ToArray());

        Span<byte> clearKey = stackalloc byte[encryptionKey.KeyLength];
        int written = cloned.Decrypt(protectionKey.GetKey(), clearKey);
        clearKey = clearKey[..written];

        // Assert
        Assert.Equivalent(keyBlock, cloned, strict: true);
        Assert.Equal(encryptionKey.GetKey(), clearKey);
    }
}