// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Security.Utilities
{
    public class UnclassifiedJwt : RegexPattern
    {
        public UnclassifiedJwt()
        {
            Id = "SEC101/528";
            Name = nameof(UnclassifiedJwt);
            Label = "an unclassified JWT token";
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.MediumConfidence;
            Pattern = @$"(?:^|[^0-9A-Za-z-_.])e[0-9A-Za-z-_=]{{23,}}\.e[0-9A-Za-z-_=]{{23,}}\.[0-9A-Za-z-_=]{{24,}}(?:[^0-9A-Za-z-_]|$)";
            // These signatures represent base64-encoding of the following
            // constants, respectively: '{"', '{" ', and '{\r\n`.
            Signatures = new HashSet<string>(["eyJ", "eyAi", "ewog"]);
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            string header = match.Substring(0, match.IndexOf('.'));
            string decoded = null;

            try
            {
                header = $"{header}{Base64Padding(header)}";
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header));
            }
            catch(FormatException)
            {
                return null;
            }

            return decoded.IndexOf("\"alg\"") != -1
                ? base.GetMatchIdAndName(match)
                : null;
        }

        public static string Base64Padding(string base64Segment)
        {
            int length = base64Segment.Length;
            int remainder = length % 4;

            if (remainder == 0)
            {
                // No padding needed
                return string.Empty;
            }
            else
            {
                // Padding needed
                return new string('=', 4 - remainder);
            }
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // Patterns for JWTs with varying prefixes in base64 encoding, a brace followed by a
            // quote, a brace followed by a space and quote, and a brace followed by a newline
            // sequence.
            yield return $"eyAidHlwIiA6ICJKV1QiLCAiYWxnIiA6ICJIUzI1NiIgfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            yield return $"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            yield return $"ewogaWQiOiJ5ZXMiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im1lIGFnYWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.i6jPt5VrHYb77j8bPA2lWWiasPAR-_xa4ZtQCJTdnjI";
        }
    }
}