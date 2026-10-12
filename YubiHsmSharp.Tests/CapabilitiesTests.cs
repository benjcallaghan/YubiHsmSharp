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

        // Act
        Capabilities capabilities = Capabilities.From(input);

        // Assert
        byte[] output = Convert.FromHexString(hexOutput);
        Assert.Equal(output, capabilities);
    }

    [Fact]
    public void CanParseCheckAndPrintCapabilities()
    {
        // Parse
        string input = "sign-pkcs:decrypt-pkcs:export-wrapped:set-option:get-pseudo-random:sign-hmac:verify-hmac:get-log-entries";
        Capabilities capabilities = Capabilities.From(input);

        // Check
        Assert.False(capabilities.CheckCapability("something"));
        Assert.False(capabilities.CheckCapability("sign-pss"));
        Assert.True(capabilities.CheckCapability("sign-pkcs"));
        Assert.True(capabilities.CheckCapability("decrypt-pkcs"));
        Assert.True(capabilities.CheckCapability("export-wrapped"));
        Assert.True(capabilities.CheckCapability("set-option"));
        Assert.True(capabilities.CheckCapability("get-pseudo-random"));
        Assert.True(capabilities.CheckCapability("sign-hmac"));
        Assert.True(capabilities.CheckCapability("verify-hmac"));
        Assert.True(capabilities.CheckCapability("get-log-entries"));
        Assert.True(capabilities.CheckCapability("verify-hmac:get-log-entries"));

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
        Capabilities c1 = Capabilities.From("sign-pkcs,sign-pss");
        Capabilities c2 = Capabilities.From("decrypt-pkcs,decrypt-oaep");
        Capabilities c3 = Capabilities.From("sign-pss,decrypt-oaep");

        // Merge
        Capabilities res = c1.Merge(in c2);
        Assert.True(res.CheckCapability("sign-pkcs"));
        Assert.True(res.CheckCapability("sign-pss"));
        Assert.True(res.CheckCapability("decrypt-pkcs"));
        Assert.True(res.CheckCapability("decrypt-oaep"));
        Assert.False(res.CheckCapability("sign-hmac"));

        // Filter
        res = res.Filter(in c3);
        Assert.False(res.CheckCapability("sign-pkcs"));
        Assert.True(res.CheckCapability("sign-pss"));
        Assert.False(res.CheckCapability("decrypt-pkcs"));
        Assert.True(res.CheckCapability("decrypt-oaep"));
        Assert.False(res.CheckCapability("sign-hmac"));
    }
}