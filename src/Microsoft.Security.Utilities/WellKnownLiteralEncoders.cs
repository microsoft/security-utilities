using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace Microsoft.Security.Utilities
{
    internal class WellKnownLiteralEncoders
    {
        public static string EscapeJsonString(string value)
        {
            // Use the relaxed encoder to prefer quotes that aren't rendered
            // as embedded unicode, e.g., '\u0022' rather than '\"'.
            return JsonEncodedText.Encode(value, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();
        }

        public static string UnescapeBackslashes(string value)
        {
            return value.Replace("\\\\", "\\")
                        .Replace("\\'", "'")
                        .Replace("\\\"", "\"")
                        .Replace("\\t", "\t");
        }

        public static string UriDataEscape(string value)
        {
            return UriDataEscape(value, 65519);
        }

        internal static string UriDataEscape(string value, int maxSegmentSize)
        {
            if (value.Length <= maxSegmentSize)
            {
                return Uri.EscapeDataString(value);
            }

            StringBuilder stringBuilder = new StringBuilder();
            int num = 0;
            do
            {
                int num2 = Math.Min(value.Length - num, maxSegmentSize);
                if (char.IsHighSurrogate(value[num + num2 - 1]) && num2 > 1)
                {
                    num2--;
                }

                stringBuilder.Append(Uri.EscapeDataString(value.Substring(num, num2)));
                num += num2;
            }
            while (num < value.Length);
            return stringBuilder.ToString();
        }
    }
}
