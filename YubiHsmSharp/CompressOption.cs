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

namespace YubiHsmSharp;

/// <summary>
/// Options for data compression
/// </summary>
public enum CompressOption
{
    /// <summary>Do not compress data before importing it</summary>
    NoCompression = 1,

    /// <summary>Compress data if it's too big</summary>
    CompressIfTooBig = 2,

    /// <summary>Compress data before importing it</summary>
    Compress = 3,
}
