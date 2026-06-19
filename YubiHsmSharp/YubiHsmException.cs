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
/// The exception that is thrown when a native YubiHSM method returns an error code.
/// </summary>
public class YubiHsmException : Exception
{
    internal YubiHsmException(yh_rc err) : base(GetErrorMessage(err))
    {
    }

    private static string GetErrorMessage(yh_rc err)
    {
        nint message = yh_strerror(err);
        return Marshal.PtrToStringUTF8(message) ?? String.Empty;
    }

    internal static void ThrowIfError(yh_rc err)
    {
        if (err != yh_rc.YHR_SUCCESS)
        {
            throw new YubiHsmException(err);
        }
    }
}