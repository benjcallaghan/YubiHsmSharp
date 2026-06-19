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

namespace YubiHsmSharp;

/// <summary>
/// Whether a device option is enabled in a device-global setting.
/// </summary>
public enum DeviceOption
{
    /// <summary>
    /// Option disabled
    /// </summary>
    Disabled = 0,

    /// <summary>
    /// Option enabled
    /// </summary>
    Enabled = 1,

    /// <summary>
    /// Option permanently enabled (only possible to turn off through factory reset)
    /// </summary>
    Permanent = 2,
}