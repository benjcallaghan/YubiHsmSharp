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
using Org.BouncyCastle.Security;

namespace YubiHsmSharp.PciPin.Tests;

[Trait("Requires", "None")]
public class Format0PinBlockTests
{
    [Theory]
    [InlineData("5678", "4111111111111111")]
    [InlineData("1234567", "4111111111111111")]
    public void Format0PinBlock_WhenEncrypted_DecryptsToOriginalPin(string testPin, string testPan)
    {
        // Arrange
        IBlockCipher cipher = new DesEdeEngine();
        CipherKeyGenerator generator = new();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 128));
        KeyParameter encryptionKey = generator.GenerateKeyParameter();

        // Act
        Format0PinBlock pinBlock = Format0PinBlock.Encrypt(cipher, encryptionKey, testPin, testPan);
        string outPin = pinBlock.Decrypt(cipher, encryptionKey, testPan);

        // Assert
        Assert.Equal(testPin, outPin);
    }
}