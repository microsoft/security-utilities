// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Unclassified32CharacterString : RegexPattern
    {
        public const string AzureContainerRegistryLegacyKey = nameof(AzureContainerRegistryLegacyKey);
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
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.Unclassified | DetectionMetadata.LowConfidence;
            Pattern = $"(?i)[a-z0-9.=\\-:[_@\\/*\\]+?]{{32}}$";
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (DateTime.TryParse(match, out DateTime result))
            {
                return null;
            }

            if (HasAtLeastOneNonBase64EncodingSymbol(match))
            {
                return new Tuple<string, string>("SEC101/101", AadClientAppLegacyCredentials);
            }

            return new Tuple<string, string>("SEC101/109", AzureContainerRegistryLegacyKey);
        }

        private const string symbols = ".=-:[_@/*]+?";
        private static readonly HashSet<char> symbolChars = new HashSet<char>(symbols.ToCharArray());

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            int sampleSize = 5;

            string alphabet = $"={WellKnownRegexPatterns.Base64}";
            yield return $"{WellKnownRegexPatterns.GenerateString(alphabet, 32)}";

            while (sampleSize > 0)
            {
                string key = WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}{symbols}", 32);
                if (AadClientAppLegacyCredentials34.HasAtLeastOneSymbol(key))
                {
                    sampleSize--;
                    yield return key;
                }
            }
        }

        internal static bool HasAtLeastOneSymbol(string text)
        {
            foreach (char c in text)
            {

                if (symbolChars.Contains(c))
                {
                    return true;
                }
            }

            return false;
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
            yield return "2024-03-07T02:50:56.464790+00:00";

            yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 31);
            yield return WellKnownRegexPatterns.GenerateString($"{WellKnownRegexPatterns.Base62}.=-:[_@/*]+?", 31);
        }

        private static bool HasAtLeastOneNonBase64EncodingSymbol(string text)
        {
            foreach (char c in text)
            {

                if (c == '.' || c == '-' || c == ':' ||
                    c == '[' || c == '_' || c == '@' ||
                    c == '*' || c == ']' || c == '?')
                {
                    return true;
                }
            }

            return false;
        }
    }
}