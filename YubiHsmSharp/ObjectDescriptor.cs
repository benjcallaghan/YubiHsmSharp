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

namespace YubiHsmSharp;

/// <summary>
/// Object descriptor
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct ObjectDescriptor
{
    /// <summary>
    /// Object capabilities
    /// </summary>
    /// <seealso cref="YubiHsmSharp.Capabilities"/> 
    public readonly Capabilities Capabilities => this.capabilities;
    private readonly Capabilities capabilities;

    /// <summary>
    /// Object ID
    /// </summary>
    public readonly ushort Id => this.id;
    private readonly ushort id;

    /// <summary>
    /// Object length
    /// </summary>
    public readonly ushort Length => this.len;
    private readonly ushort len;

    /// <summary>
    /// Object domains
    /// </summary>
    public readonly ushort Domains => this.domains;
    private readonly ushort domains;

    /// <summary>
    /// Object type
    /// </summary>
    public readonly ObjectType Type => this.type;
    private readonly ObjectType type;

    /// <summary>
    /// Object algorithm
    /// </summary>
    public readonly Algorithm Algorithm => this.algorithm;
    private readonly Algorithm algorithm;

    /// <summary>
    /// Object sequence
    /// </summary>
    public readonly byte Sequence => this.sequence;
    private readonly byte sequence;

    /// <summary>
    /// Object origin
    /// </summary>
    public readonly byte Origin => this.origin;
    private readonly byte origin;

    /// <summary>
    /// Object label. The label consists of raw bytes and is not restricted to
    /// printable characters or valid UTF-8 glyphs.
    /// </summary>
    public readonly unsafe ReadOnlySpan<byte> Label => 
        MemoryMarshal.CreateReadOnlySpanFromNullTerminated(
            (byte*)Unsafe.AsPointer(ref Unsafe.AsRef(in this.label))
        );
    private readonly ObjectLabel label;

    /// <summary>
    /// Object delegated capabilities.
    /// </summary>
    public readonly Capabilities DelegatedCapabilities => this.delegated_capabilities;
    private readonly Capabilities delegated_capabilities;
}

[InlineArray(YH_OBJ_LABEL_LEN + 1)]
internal struct ObjectLabel
{
    private byte _element;
}
