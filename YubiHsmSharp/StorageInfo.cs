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
/// Information about the free storage of the device.
/// </summary>
/// <param name="TotalRecords">Total number of records.</param>
/// <param name="FreeRecords">Number of free records.</param>
/// <param name="TotalPages">Total number of pages.</param>
/// <param name="FreePages">Number of free pages.</param>
/// <param name="PageSize">Page size in bytes.</param>
public record class StorageInfo(ushort TotalRecords, ushort FreeRecords, ushort TotalPages, ushort FreePages, ushort PageSize);