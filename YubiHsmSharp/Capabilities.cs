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

using System.Runtime.CompilerServices;
using System.Text;

namespace YubiHsmSharp;

/// <summary>
/// Capabilities representation
/// </summary>
[InlineArray(YH_CAPABILITIES_LEN)]
public struct Capabilities
{
    private byte _element;

    /// <summary>
    /// Converts a string representation of capabilities to a <see cref="Capabilities"/> struct.
    /// </summary>
    /// <param name="utf8String">String of capabilities separated by ',', ':', or '|', UTF-8 encoded and null-terminated.</param>
    /// <returns>The parsed capabilities.</returns>
    public static Capabilities From(ReadOnlySpan<byte> utf8String)
    {
        yh_rc err = yh_string_to_capabilities(utf8String, out Capabilities caps);
        YubiHsmException.ThrowIfError(err);
        return caps;
    }

    /// <summary>
    /// Converts the capabilities into a comma-separated string.
    /// </summary>
    /// <returns>A string representation of the capabilities.</returns>
    public readonly override string ToString()
    {
        const int maxCapabilities = 56;
        Span<nint> stringPtrs = stackalloc nint[maxCapabilities];
        yh_rc err = yh_capabilities_to_strings(in this, stringPtrs, out nuint stringsLen);
        YubiHsmException.ThrowIfError(err);

        stringPtrs = stringPtrs[..(int)stringsLen];
        StringBuilder builder = new();

        foreach (nint ptr in stringPtrs)
        {
            var value = Marshal.PtrToStringUTF8(ptr);
            builder.Append(value);
            builder.Append(',');
        }

        return builder.ToString();
    }

    /// <summary>
    /// Checks if a capability is set.
    /// </summary>
    /// <param name="utf8Capability">Capability to check, UTF-8 encoded and null-terminated.</param>
    /// <returns>True if the capability is in this capabilities set. False otherwise.</returns>
    public readonly bool CheckCapability(ReadOnlySpan<byte> utf8Capability)
    {
        return yh_check_capability(in this, utf8Capability);
    }

    /// <summary>
    /// Merges this set of capabilities with another set. The result set contains all capabilities from both sets.
    /// </summary>
    /// <param name="other">The set of capabilites to merge in.</param>
    /// <returns>The merged set of capabilities.</returns>
    public readonly Capabilities Merge(in Capabilities other)
    {
        yh_rc err = yh_merge_capabilities(in this, in other, out Capabilities result);
        YubiHsmException.ThrowIfError(err);
        return result;
    }

    /// <summary>
    /// Filters this set of capabilities with another. The result set contains only the capabilites that exist in both sets.
    /// </summary>
    /// <param name="filter">The set of capabilities to keep.</param>
    /// <returns>The filtered set of capabilities.</returns>
    public readonly Capabilities Filter(in Capabilities filter)
    {
        yh_rc err = yh_filter_capabilities(in this, in filter, out Capabilities result);
        YubiHsmException.ThrowIfError(err);
        return result;
    }
}
