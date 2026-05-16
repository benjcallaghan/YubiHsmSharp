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

using System.Runtime.InteropServices;
using System.Text;

namespace YubiHsmSharp.Tests;

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
        Span<sbyte> inputBytes = stackalloc sbyte[input.Length + 1];
        int inputLength = Encoding.UTF8.GetBytes(input, MemoryMarshal.Cast<sbyte, byte>(inputBytes));
        inputBytes[^1] = 0; // Null-terminated
        Assert.Equal(input.Length, inputLength); // All values fit within ASCII.

        // Act
        Capabilities capabilities = Capabilities.From(inputBytes);

        // Assert
        byte[] output = Convert.FromHexString(hexOutput);
        Assert.Equal(output, capabilities);
    }

    [Fact]
    public void CanParseCheckAndPrintCapabilities()
    {
        // Parse
        ReadOnlySpan<sbyte> input = MemoryMarshal.Cast<byte, sbyte>("sign-pkcs:decrypt-pkcs:export-wrapped:set-option:get-pseudo-random:sign-hmac:verify-hmac:get-log-entries"u8);
        Capabilities capabilities = Capabilities.From(input);

        // Check
        Assert.False(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("something"u8)));
        Assert.False(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pss"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pkcs"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("decrypt-pkcs"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("export-wrapped"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("set-option"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("get-pseudo-random"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-hmac"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("verify-hmac"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("get-log-entries"u8)));
        Assert.True(capabilities.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("verify-hmac:get-log-entries"u8)));

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
        Capabilities c1 = Capabilities.From(MemoryMarshal.Cast<byte, sbyte>("sign-pkcs,sign-pss"u8));
        Capabilities c2 = Capabilities.From(MemoryMarshal.Cast<byte, sbyte>("decrypt-pkcs,decrypt-oaep"u8));
        Capabilities c3 = Capabilities.From(MemoryMarshal.Cast<byte, sbyte>("sign-pss,decrypt-oaep"u8));

        // Merge
        Capabilities res = c1.Merge(in c2);
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pkcs"u8)));
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pss"u8)));
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("decrypt-pkcs"u8)));
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("decrypt-oaep"u8)));
        Assert.False(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-hmac"u8)));

        // Filter
        res = res.Filter(in c3);
        Assert.False(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pkcs"u8)));
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-pss"u8)));
        Assert.False(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("decrypt-pkcs"u8)));
        Assert.True(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("decrypt-oaep"u8)));
        Assert.False(res.CheckCapability(MemoryMarshal.Cast<byte, sbyte>("sign-hmac"u8)));
    }
}