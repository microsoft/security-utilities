// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AadClientAppLegacyCredentials32 : RegexPattern
    {
        public const string AadClientAppLegacyCredentials = nameof(AadClientAppLegacyCredentials);


        /// <summary>
        /// Detect 32-character Azure Active Directory client application legacy credentials.
        /// The generated key is a 32-character string that contains alphanumeric characters
        /// as well as symbols from the set: .=\-:[_@\*]+?
        /// </summary>
        public AadClientAppLegacyCredentials32()
        {
            Id = "SEC101/101";
            Name = AadClientAppLegacyCredentials;
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat;
            Pattern = $"^(?i)[a-z0-9.=\\-:[_@\\/*\\]+?]{{32}}$";
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (!HasAtLeastOneSymbol(match))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            while (true)
            {
                string key = WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);
                if (HasAtLeastOneSymbol(key))
                {
                    yield return key;
                    break;
                }
            }
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
        }


        private static bool HasAtLeastOneSymbol(string text)
        {
            foreach (char c in text)
            {

                if (c == '.' || c == '=' || c == '-' || c == ':' ||
                    c == '[' || c == '_' || c == '@' || c == '/' ||
                    c == '*' || c == ']' || c == '+' || c == '?')
                {
                    return true;
                }
            }

            return false;
        }
    }
}