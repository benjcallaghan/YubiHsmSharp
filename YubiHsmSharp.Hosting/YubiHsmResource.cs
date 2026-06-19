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

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Represents a YubiHSM 2 resource that can be used by an application.
/// </summary>
public class YubiHsmResource(string name, string url) : Resource(name), IResourceWithConnectionString
{
    internal string Url => url;

    internal ParameterResource? AuthKeyId { get; set; }

    internal ParameterResource? Password { get; set; }

    /// <inheritdoc />
    public ReferenceExpression ConnectionStringExpression => ReferenceExpression.Create(
        $"Url={this.Url};AuthKeyId={this.AuthKeyId!};Password={this.Password!}"
    );
}
