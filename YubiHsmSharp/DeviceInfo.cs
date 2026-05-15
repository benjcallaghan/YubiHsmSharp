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
/// Device info struct
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct DeviceInfo
{
    /// <summary>
    /// Fimrware version major
    /// </summary>
    public readonly byte Major => this.major;
    private readonly byte major;

    /// <summary>
    /// Firmware version minor
    /// </summary>
    public readonly byte Minor => this.minor;
    private readonly byte minor;

    /// <summary>
    /// Firmware version patch
    /// </summary>
    public readonly byte Patch => this.patch;
    private readonly byte patch;

    /// <summary>
    /// Device serial number
    /// </summary>
    public readonly uint Serial => this.serial;
    private readonly uint serial;

    /// <summary>
    /// Total available logs
    /// </summary>
    public readonly byte LogTotal => this.log_total;
    private readonly byte log_total;

    /// <summary>
    /// Total used logs
    /// </summary>
    public readonly byte LogUsed => this.log_used;
    private readonly byte log_used;

    /// <summary>
    /// List of algorithms supported by the device
    /// </summary>
    public readonly ReadOnlySpan<Algorithm> Algorithms => 
        MemoryMarshal.CreateReadOnlySpan(
            ref Unsafe.As<DeviceAlgorithms, Algorithm>(ref Unsafe.AsRef(in this.algorithms)),
            (int)this.n_algorithms);
    private readonly DeviceAlgorithms algorithms;

    /// <summary>
    /// Number of algorithms supported by the device
    /// </summary>
    private readonly nuint n_algorithms;
}

[InlineArray(YH_MAX_ALGORITHM_COUNT)]
internal struct DeviceAlgorithms
{
    private Algorithm _element;
}
