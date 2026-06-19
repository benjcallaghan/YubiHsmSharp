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
using System.Text;

namespace YubiHsmSharp;

/// <summary>
/// A collection of Domains, logical partitions that can be conceptually mapped to a container.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct Domains
{
    /// <summary>
    /// Constructs a collection of domains from a raw numeric value.
    /// </summary>
    /// <param name="rawValue">The raw numeric bit flags of the domains collection.</param>
    public Domains(ushort rawValue)
    {
        this.domains = rawValue;
    }

    /// <summary>
    /// Gets the raw numeric representation of the domains.
    /// </summary>
    public readonly ushort RawValue => this.domains;
    private readonly ushort domains;

    /// <summary>
    /// Convert a string to a domain's numeric value.
    /// </summary>
    /// <remarks>
    /// The domains string can contain one or several domains separated by ',', ':', or '|'.
    /// Each domain can be written in decimal or hex format.
    /// </remarks>
    /// <param name="utf8String">String of domains, UTF-8 encoded and null-terminated.</param>
    /// <returns>The parsed domains as an unsigned int.</returns>
    public static Domains From(ReadOnlySpan<byte> utf8String)
    {
        yh_rc err = yh_string_to_domains(utf8String, out Domains result);
        YubiHsmException.ThrowIfError(err);
        return result;
    }

    /// <summary>
    /// Converts domains to its string representation.
    /// </summary>
    /// <returns>The string representation of the domains.</returns>
    public override string ToString()
    {
        const int maxLength = 40;
        Span<byte> utf8Bytes = stackalloc byte[maxLength];
        yh_rc err = yh_domains_to_string(this, utf8Bytes, maxLength);
        YubiHsmException.ThrowIfError(err);

        int terminator = utf8Bytes.IndexOf((byte)0);
        Debug.Assert(terminator != -1, "The null terminator must be present in result.");
        return Encoding.UTF8.GetString(utf8Bytes[..terminator]);
    }
}