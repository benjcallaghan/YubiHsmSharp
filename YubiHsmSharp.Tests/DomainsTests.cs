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

public class DomainsTests
{
    [Theory]
    [InlineData("1", 1)]
    [InlineData("1,16", 0x8001)]
    [InlineData("16,15", 0xc000)]
    [InlineData("0x1,0x2", 3)]
    [InlineData("0", 0)]
    [InlineData("2", 2)]
    [InlineData("1,2:3,4|5,6;7,8,9,10,11,12,13,14,15,16", 0xffff)]
    [InlineData("16", 0x8000)]
    [InlineData("1,0xf", 0x4001)]
    [InlineData("0x8888", 0x8888)]
    [InlineData("all", 0xffff)]
    [InlineData("2:4", 10)]
    public void From_WithValidString_ProducesValidNumeric(string input, ushort output)
    {
        // Arrange
        Span<byte> utf8Input = stackalloc byte[input.Length + 1];
        int inputLength = Encoding.UTF8.GetBytes(input, utf8Input);
        utf8Input[^1] = 0; // Null-terminated
        Assert.Equal(input.Length, inputLength); // All values fit within ASCII.

        // Act
        Domains domains = Domains.From(utf8Input);

        // Assert
        Assert.Equal(output, domains.RawValue);
    }

    [Theory]
    [InlineData(1, "1")]
    [InlineData(0x8001, "1:16")]
    [InlineData(0, "")]
    [InlineData(0xffff, "1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16")]
    public void ToString_WithValidNumeric_ProducesValidString(ushort input, string output)
    {
        // Arrange
        Domains domains = new(input);

        // Act
        string result = domains.ToString();

        // Assert
        Assert.Equal(output, result);
    }
}
