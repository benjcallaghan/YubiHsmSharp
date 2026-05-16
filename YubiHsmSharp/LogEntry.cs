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
/// Logging struct as returned by device
/// </summary>
/// <seealso href="https://developers.yubico.com/YubiHSM2/Concepts/Logs.html"/> 
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public readonly struct LogEntry
{
    /// <summary>
    /// Monotonically increasing index
    /// </summary>
    public readonly ushort Number => this.number;
    private readonly ushort number;

    /// <summary>
    /// What command was executed
    /// </summary>
    /// <seealso cref="Command"/> 
    public readonly Command Command => this.command;
    private readonly Command command;

    /// <summary>
    /// Length of in-data
    /// </summary>
    public readonly ushort Length => this.length;
    private readonly ushort length;

    /// <summary>
    /// ID of Authentication Key used
    /// </summary>
    public readonly ushort SessionKey => this.session_key;
    private readonly ushort session_key;

    /// <summary>
    /// ID of first Object used
    /// </summary>
    public readonly ushort TargetKey => this.target_key;
    private readonly ushort target_key;

    /// <summary>
    /// ID of second Object used
    /// </summary>
    public readonly ushort SecondKey => this.second_key;
    private readonly ushort second_key;

    /// <summary>
    /// Command result
    /// </summary>
    /// <seealso cref="Command"/> 
    public readonly Command Result => this.result;
    private readonly Command result;

    /// <summary>
    /// Systick at time of execution
    /// </summary>
    public readonly uint Systick => this.systick;
    private readonly uint systick;

    /// <summary>
    /// Truncated sha256 digest of this last digest + this entry
    /// </summary>
    public readonly ReadOnlySpan<byte> Digest =>
        MemoryMarshal.CreateReadOnlySpan(
            ref Unsafe.As<LogDigest, byte>(ref Unsafe.AsRef(in this.digest)),
            YH_LOG_DIGEST_SIZE
        );
    private readonly LogDigest digest;
}

[InlineArray(YH_LOG_DIGEST_SIZE)]
internal struct LogDigest
{
    private byte _element;
}
