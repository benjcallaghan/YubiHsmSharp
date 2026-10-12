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

namespace YubiHsmSharp.Tests;

[Trait("Requires", "YubiSDK")]
public class AlgorithmTests
{
    [Theory]
    [InlineData(Algorithm.Rsa2048, false)]
    [InlineData(Algorithm.HmacSha1, true)]
    [InlineData(Algorithm.HmacSha256, true)]
    [InlineData(Algorithm.HmacSha384, true)]
    [InlineData(Algorithm.HmacSha512, true)]
    public void IsHMAC_WithValidAlgorithm_ReturnsCorrectResult(Algorithm input, bool output)
    {
        Assert.Equal(output, input.IsHmac);
    }

    [Theory]
    [InlineData("")]
    [InlineData("something")]
    public void From_WithInvalidString_ThrowsYubiHsmException(string input)
    {
        // Arrange

        // Act
        Action act = () => Algorithm.From(input);

        // Assert
        Assert.Throws<YubiHsmException>(act);
    }

    [Theory]
    [InlineData("rsa-pkcs1-sha1", Algorithm.RsaPkcs1Sha1)]
    [InlineData("rsa2048", Algorithm.Rsa2048)]
    [InlineData("ecp384", Algorithm.Ecp384)]
    [InlineData("mgf1-sha512", Algorithm.Mgf1Sha512)]
    public void From_WithValidString_ProducesValidAlgorithm(string input, Algorithm output)
    {
        // Arrange

        // Act
        Algorithm algorithm = Algorithm.From(input);

        // Assert
        Assert.Equal(output, algorithm);
    }
}