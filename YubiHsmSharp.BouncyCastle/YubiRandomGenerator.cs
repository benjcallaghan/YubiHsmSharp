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

using System.Diagnostics;
using Org.BouncyCastle.Crypto.Prng;

namespace YubiHsmSharp.BouncyCastle;

/// <summary>
/// A random number generator that uses the pseudo-random functionality of the YubiHSM 2.
/// </summary>
/// <remarks>
/// The authentication key used to create the session must have the following capabilities: get-pseudo-random.
/// </remarks>
/// <param name="session">The authenticated session to the YubiHSM 2.</param>
public class YubiRandomGenerator(YubiSession session) : IRandomGenerator
{
    /// <inheritdoc />
    public void AddSeedMaterial(byte[] seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void AddSeedMaterial(ReadOnlySpan<byte> seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void AddSeedMaterial(long seed)
    {
        throw new NotSupportedException("YubiHSM 2 does not support seeded random values.");
    }

    /// <inheritdoc />
    public void NextBytes(byte[] bytes) => NextBytes(bytes.AsSpan());

    /// <inheritdoc />
    public void NextBytes(byte[] bytes, int start, int len) => NextBytes(bytes.AsSpan(start, len));

    /// <inheritdoc />
    public void NextBytes(Span<byte> bytes)
    {
        int written = session.GetPseudoRandom(bytes);
        Debug.Assert(written == bytes.Length);
    }
}