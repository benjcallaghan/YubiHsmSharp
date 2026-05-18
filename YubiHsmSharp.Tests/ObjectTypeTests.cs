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

public class ObjectTypeTests
{
    [Theory]
    [InlineData("")]
    [InlineData("something")]
    public void From_WithInvalidString_ThrowsYubiHsmException(string input)
    {
        Action act = () =>
        {
            // Arrange
            Span<byte> utf8Input = stackalloc byte[input.Length + 1];
            int inputLength = Encoding.UTF8.GetBytes(input, utf8Input);
            utf8Input[^1] = 0; // Null-terminated
            Assert.Equal(input.Length, inputLength); // All values fit within ASCII.

            // Act
            ObjectType.From(utf8Input);
        };

        // Assert
        Assert.Throws<YubiHsmException>(act);
    }

    [Theory]
    [InlineData("opaque", ObjectType.Opaque)]
    [InlineData("authentication-key", ObjectType.AuthenticationKey)]
    [InlineData("asymmetric-key", ObjectType.AsymmetricKey)]
    [InlineData("wrap-key", ObjectType.WrapKey)]
    [InlineData("hmac-key", ObjectType.HmacKey)]
    [InlineData("template", ObjectType.Template)]
    [InlineData("otp-aead-key", ObjectType.OtpAeadKey)]
    public void From_WithValidString_ProducesValidObjectType(string input, ObjectType output)
    {
        // Arrange
        Span<byte> utf8Input = stackalloc byte[input.Length + 1];
        int inputLength = Encoding.UTF8.GetBytes(input, utf8Input);
        utf8Input[^1] = 0; // Null-terminated
        Assert.Equal(input.Length, inputLength); // All values fit within ASCII.

        // Act
        ObjectType type = ObjectType.From(utf8Input);

        // Assert
        Assert.Equal(output, type);
    }

    [Theory]
    [InlineData((ObjectType)99, "Unknown")]
    [InlineData(ObjectType.Opaque, "opaque")]
    [InlineData(ObjectType.AuthenticationKey, "authentication-key")]
    [InlineData(ObjectType.AsymmetricKey, "asymmetric-key")]
    [InlineData(ObjectType.WrapKey, "wrap-key")]
    [InlineData(ObjectType.HmacKey, "hmac-key")]
    [InlineData(ObjectType.Template, "template")]
    [InlineData(ObjectType.OtpAeadKey, "otp-aead-key")]
    public void ToString_WithValidObjectType_ProducesValidString(ObjectType input, string output)
    {
        // Act
        string result = input.ToYubiString();

        // Assert
        Assert.Equal(output, result);
    }
}