// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;

namespace Microsoft.Security.Utilities
{
    public class WellKnownLiteralEncoders
    {
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
