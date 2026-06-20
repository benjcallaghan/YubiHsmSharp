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

namespace YubiHsmSharp.PciPin.Tests;

[Trait("Requires", "None")]
public class UnitTest1
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

        // Act
        Span<byte> keyCheckValue = stackalloc byte[3];
        int written = KeyUtils.AesKeyCheckValue(key, keyCheckValue);
        keyCheckValue = keyCheckValue[..written];

        // Assert
        byte[] checkValue = Convert.FromHexString(hexCheckValue);
        Assert.Equal(checkValue, keyCheckValue);
    }
}
