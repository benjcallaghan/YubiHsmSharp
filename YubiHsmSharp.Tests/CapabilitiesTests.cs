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

using System.Text;

namespace YubiHsmSharp.Tests;

[Trait("Requires", "YubiSDK")]
public class CapabilitiesTests
{
    [Theory]
    [InlineData("get-opaque", "0000000000000001")]
    [InlineData("sign-hmac:verify-hmac|exportable-under-wrap,", "0000000000c10000")]
    [InlineData(",,unwrap-data|:wrap-data,,,", "0000006000000000")]
    [InlineData("0x7fffffffffffffff", "7fffffffffffffff")]
    [InlineData("0xffffffffffffffff", "ffffffffffffffff")]
    public void From_WithValidString_ProducesValidNumeric(string input, string hexOutput)
    {
        // Arrange
        Span<byte> utf8Input = stackalloc byte[input.Length + 1];
        int inputLength = Encoding.UTF8.GetBytes(input, utf8Input);
        utf8Input[^1] = 0; // Null-terminated
        Assert.Equal(input.Length, inputLength); // All values fit within ASCII.

        // Act
        Capabilities capabilities = Capabilities.From(utf8Input);

        // Assert
        byte[] output = Convert.FromHexString(hexOutput);
        Assert.Equal(output, capabilities);
    }

    [Fact]
    public void CanParseCheckAndPrintCapabilities()
    {
        // Parse
        ReadOnlySpan<byte> utf8Input = "sign-pkcs:decrypt-pkcs:export-wrapped:set-option:get-pseudo-random:sign-hmac:verify-hmac:get-log-entries"u8;
        Capabilities capabilities = Capabilities.From(utf8Input);

        // Check
        Assert.False(capabilities.CheckCapability("something"u8));
        Assert.False(capabilities.CheckCapability("sign-pss"u8));
        Assert.True(capabilities.CheckCapability("sign-pkcs"u8));
        Assert.True(capabilities.CheckCapability("decrypt-pkcs"u8));
        Assert.True(capabilities.CheckCapability("export-wrapped"u8));
        Assert.True(capabilities.CheckCapability("set-option"u8));
        Assert.True(capabilities.CheckCapability("get-pseudo-random"u8));
        Assert.True(capabilities.CheckCapability("sign-hmac"u8));
        Assert.True(capabilities.CheckCapability("verify-hmac"u8));
        Assert.True(capabilities.CheckCapability("get-log-entries"u8));
        Assert.True(capabilities.CheckCapability("verify-hmac:get-log-entries"u8));

        // Print
        string output = capabilities.ToString();
        Assert.Contains("sign-pkcs", output);
        Assert.Contains("decrypt-pkcs", output);
        Assert.Contains("export-wrapped", output);
        Assert.Contains("set-option", output);
        Assert.Contains("get-pseudo-random", output);
        Assert.Contains("sign-hmac", output);
        Assert.Contains("verify-hmac", output);
        Assert.Contains("get-log-entries", output);
    }

    [Fact]
    public void CanMergeAndFilter()
    {
        // Arrange
        Capabilities c1 = Capabilities.From("sign-pkcs,sign-pss"u8);
        Capabilities c2 = Capabilities.From("decrypt-pkcs,decrypt-oaep"u8);
        Capabilities c3 = Capabilities.From("sign-pss,decrypt-oaep"u8);

        // Merge
        Capabilities res = c1.Merge(in c2);
        Assert.True(res.CheckCapability("sign-pkcs"u8));
        Assert.True(res.CheckCapability("sign-pss"u8));
        Assert.True(res.CheckCapability("decrypt-pkcs"u8));
        Assert.True(res.CheckCapability("decrypt-oaep"u8));
        Assert.False(res.CheckCapability("sign-hmac"u8));

        // Filter
        res = res.Filter(in c3);
        Assert.False(res.CheckCapability("sign-pkcs"u8));
        Assert.True(res.CheckCapability("sign-pss"u8));
        Assert.False(res.CheckCapability("decrypt-pkcs"u8));
        Assert.True(res.CheckCapability("decrypt-oaep"u8));
        Assert.False(res.CheckCapability("sign-hmac"u8));
    }
}