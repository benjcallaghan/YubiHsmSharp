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

namespace YubiHsmSharp.PciPin.Tests;

[Trait("Requires", "None")]
public class KeyUtilsTests
{
    [Theory]
    [InlineData("1234567890ABCDEFFEDCBA0987654321", "3F077B")]
    [InlineData("00112233445566778899AABBCCDDEEFF", "53E107")]
    [InlineData("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", "0C1589")]
    [InlineData("0000111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF", "F66591")]
    public void AesKeyCheckValue_WithValidKey_ProducesValidCheckValue(string hexKey, string hexCheckValue)
    {
        // Arrange
        byte[] key = Convert.FromHexString(hexKey);
        IBlockCipher cipher = AesUtilities.CreateEngine();

        // Act
        Span<byte> keyCheckValue = stackalloc byte[3];
        int written = KeyUtils.KeyCheckValue(cipher, key, keyCheckValue);
        keyCheckValue = keyCheckValue[..written];

        // Assert
        byte[] checkValue = Convert.FromHexString(hexCheckValue);
        Assert.Equal(checkValue, keyCheckValue);
    }

    [Fact]
    public void CombineComponents_WithValidComponents_ProducesKey()
    {
        // Arrange
        ReadOnlySpan<byte> kc1 = [0x98, 0x8A, 0x59, 0xD7, 0x27, 0x31, 0x86, 0xB8,
                                  0xC9, 0xC9, 0x92, 0x2B, 0x6D, 0x40, 0xBA, 0x75];
        ReadOnlySpan<byte> kc2 = [0x89, 0x36, 0xE5, 0x26, 0x9A, 0xDF, 0xAB, 0xE7,
                                  0xD4, 0x82, 0x9B, 0x2E, 0xFB, 0x3B, 0xF5, 0xD9];
        ReadOnlySpan<byte> kc3 = [0x10, 0x9F, 0xF9, 0x96, 0x34, 0x45, 0xE0, 0xB0,
                                  0xE3, 0x97, 0xB3, 0x9D, 0xE0, 0x2F, 0x7D, 0xBC];
        ReadOnlySpan<byte> key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];

        // Act
        Span<byte> buffer = stackalloc byte[16];
        int written = KeyUtils.CombineComponents(kc1, kc2, kc3, buffer);
        buffer = buffer[..written];

        // Assert
        Assert.Equal(key, buffer);
    }
}
