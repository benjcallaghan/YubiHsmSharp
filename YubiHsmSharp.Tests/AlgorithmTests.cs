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

public class AlgorithmTests
{
    [Fact]
    public void TestAlgorithms()
    {
        // HMAC Test
        Assert.False(Algorithm.Rsa2048.IsHmac);
        Assert.True(Algorithm.HmacSha1.IsHmac);
        Assert.True(Algorithm.HmacSha256.IsHmac);
        Assert.True(Algorithm.HmacSha384.IsHmac);
        Assert.True(Algorithm.HmacSha512.IsHmac);

        // String Parsing Errors
        Assert.Throws<YubiHsmException>(() => Algorithm.From(""u8));
        Assert.Throws<YubiHsmException>(() => Algorithm.From("something"u8));

        // String Parsing Success
        Assert.Equal(Algorithm.RsaPkcs1Sha1, Algorithm.From("rsa-pkcs1-sha1"u8));
        Assert.Equal(Algorithm.Rsa2048, Algorithm.From("rsa2048"u8));
        Assert.Equal(Algorithm.Ecp384, Algorithm.From("ecp384"u8));
        Assert.Equal(Algorithm.Mgf1Sha512, Algorithm.From("mgf1-sha512"u8));
    }
}