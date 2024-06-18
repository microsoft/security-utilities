// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Unclassified32CharacterString : RegexPattern
    {
        public const string AadClientAppLegacyCredentials = nameof(AadClientAppLegacyCredentials);


        /// <summary>
        /// Detect 32-character Azure Active Directory client application legacy credentials.
        /// The generated key is a 32-character string that contains alphanumeric characters
        /// as well as symbols from the set: .=\-:[_@\*]+?
        /// </summary>
        public Unclassified32CharacterString()
        {
            Id = "SEC000/003";
            Name = nameof(Unclassified32CharacterString);
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat;
            Pattern = $"^(?i)[a-z0-9.=\\-:[_@\\/*\\]+?]{{32}}$";
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (DateTime.TryParse(match, out DateTime result))
            {
                return null;
            }

            if (!HasAtLeastOneSymbol(match))
            {
                return new Tuple<string, string>("SEC000/003", "PotentialAzureContainerRegistryLegacyKey");
            }

            return new Tuple<string, string>("SEC000/003", "PotentialAadClientAppLegacyCredentials");
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

                yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);
                yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);
                yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);
                yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);
                yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 32);

                string alphabet = $"={WellKnownRegexPatterns.Base64}";
                yield return $"{WellKnownRegexPatterns.GenerateString(alphabet, 32)}";
            }
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
            yield return "2024-03-07T02:50:56.464790+00:00";

            yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 31);
            yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 31);
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