// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class UnclassifiedLegacyCommonAnnotatedSecurityKey : RegexPattern, IHighPerformanceScannableKey
    {
        // NOTE: Use 4 character signature for high-performance scanner compatibility.
        public const string LegacyCaskSignature = "JQQJ";
        public const string LegacyCaskPattern = $"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>[{WellKnownRegexPatterns.Base62}]{{52}}{LegacyCaskSignature}9(?:9|D|H)[{WellKnownRegexPatterns.Base62}][A-L][{WellKnownRegexPatterns.Base62}]{{16}}[A-Za-z][{WellKnownRegexPatterns.Base62}]{{7}}(?:[{WellKnownRegexPatterns.Base62}]{{2}}==)?)";

        public UnclassifiedLegacyCommonAnnotatedSecurityKey()
        {
            Id = "SEC101/200";
            Name = nameof(UnclassifiedLegacyCommonAnnotatedSecurityKey);
            Label = "an unclassified legacy common annotated security key";
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = LegacyCaskPattern;
            Signatures = new HashSet<string>([LegacyCaskSignature]);
        }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => [
            new(LegacyCaskSignature,
                MakeHighPerformancePattern(LegacyCaskPattern, LegacyCaskSignature),
                signaturePrefixLength: 52,
                minMatchLength: 84,
                maxMatchLength: 88),
        ];
#endif

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            string providerSignature = match.Substring(LegacyCommonAnnotatedSecurityKey.ProviderFixedSignatureOffset, 4);

            return LegacyCaskProviderSignatures.All.Contains(providerSignature)
                ? null
                : new Tuple<string, string>(Id, Name);
        }

        public override Version CreatedVersion => Releases.Version_01_04_24;

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            foreach (bool longForm in new[] { true, false })
            {
                for (int i = 0; i < 62; i++)
                {
                    char testChar = CustomAlphabetEncoder.DefaultBase62Alphabet[i];

                    string key = null;

                    foreach (char keyKindSignature in new[] { '9', 'D', 'H' })
                    {
                        key = IdentifiableSecrets.GenerateCommonAnnotatedTestKey(randomBytes: null,
                                                                                 IdentifiableSecrets.VersionTwoChecksumSeed,
                                                                                 "TEST",
                                                                                 customerManagedKey: true,
                                                                                 platformReserved: null,
                                                                                 providerReserved: null,
                                                                                 longForm,
                                                                                 testChar,
                                                                                 keyKindSignature);
                    }

                    yield return key;

                    foreach (string prefix in s_nonInvalidatingPrefixes)
                    {
                        yield return $"{prefix}{key}";
                    }

                    foreach (string suffix in s_nonInvalidatingSuffixes)
                    {
                        yield return $"{key}{suffix}";
                    }
                }
            }
        }

        private static readonly string[] s_nonInvalidatingPrefixes = new[]
        {
            "=",
        };

        private static readonly string[] s_nonInvalidatingSuffixes = new[]
        {
            ";",
        };
    }
}
