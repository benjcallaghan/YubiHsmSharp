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

using System.ComponentModel.DataAnnotations;
using System.Data.Common;

namespace YubiHsmSharp.Client;

/// <summary>
/// Options for configuring a <see cref="YubiSession"/>.
/// </summary>
public class YubiHsmOptions
{
    internal const string DefaultConfigSectionName = "YubiHsm";

    /// <summary>
    /// Gets or sets the URL used to connect to a YubiHSM 2.
    /// </summary>
    [Required]
    public string Url { get; set; } = null!;

    /// <summary>
    /// Gets or sets whether health checks for this YubiHSM 2 should be disabled.
    /// </summary>
    public bool DisableHealthChecks { get; set; }

    /// <summary>
    /// Gets or sets whether device metrics pulled from the YubiHSM 2 should be disabled.
    /// </summary>
    public bool DisableMetrics { get; set; }

    /// <summary>
    /// Gets or sets whether device logs pulled from the YubiHSM 2 should be disabled.
    /// </summary>
    /// <remarks>
    /// When false, the authentication key identified by <see cref="AuthKeyId"/> must have the following capabilities:
    /// get-log-entries.
    /// </remarks>
    public bool DisableDeviceLogs { get; set; }

    /// <summary>
    /// Gets or sets the interval at which the YubiHSM 2 should be polled for metrics and logs.
    /// </summary>
    /// <remarks>
    /// This value is ignored if both <see cref="DisableMetrics"/> and <see cref="DisableDeviceLogs"/> are true.
    /// </remarks>
    public TimeSpan TelemetryPollInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the ID of the Authentication Key used to connect.
    /// </summary>
    [Required]
    public ObjectId AuthKeyId { get; set; }

    /// <summary>
    /// Gets or sets the password associated with the Authentication Key.
    /// </summary>
    [Required]
    public string Password { get; set; } = null!;

    internal void ParseConnectionString(string? connectionString)
    {
        if (String.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException("Connection string is missing. It should be provided in 'ConnectionStrings:<connectionName>'.");
        }

        var builder = new DbConnectionStringBuilder
        {
            ConnectionString = connectionString
        };

        if (builder.TryGetValue("Url", out var url))
        {
            this.Url = Convert.ToString(url)!;
        }
        if (builder.TryGetValue("AuthKeyId", out var authKeyId))
        {
            this.AuthKeyId = new ObjectId(Convert.ToUInt16(authKeyId));
        }
        if (builder.TryGetValue("Password", out var password))
        {
            this.Password = Convert.ToString(password)!;
        }
    }
}
