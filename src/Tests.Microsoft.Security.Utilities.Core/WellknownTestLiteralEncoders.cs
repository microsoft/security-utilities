// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Encodings.Web;
using System.Text.Json;

namespace Microsoft.Security.Utilities
{
    public sealed class WellKnownTestLiteralEncoders
    {
        public static string EscapeJsonString(string value)
        {
            // Use the relaxed encoder to prefer quotes that aren't rendered
            // as embedded unicode, e.g., '\u0022' rather than '\"'.
            return JsonEncodedText.Encode(value, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();
        }

    }
}
