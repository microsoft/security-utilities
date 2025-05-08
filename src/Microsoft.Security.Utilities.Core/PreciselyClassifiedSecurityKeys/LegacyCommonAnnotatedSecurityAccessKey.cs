// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public abstract class LegacyCommonAnnotatedSecurityAccessKey : RegexPattern, IHighPerformanceScannableKey
    {
        protected const string LegacyCaskSignature = "JQQJ";

        abstract protected string ProviderSignature { get; }

        protected virtual string PlatformData => $"[{WellKnownRegexPatterns.Base62}]{{12}}";

        protected virtual string ProviderData => $"AAAA";

        public LegacyCommonAnnotatedSecurityAccessKey()
        {
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = $"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>[{WellKnownRegexPatterns.Base62}]{{52}}JQQJ99[{WellKnownRegexPatterns.Base62}][A-L]{PlatformData}{ProviderData}{ProviderSignature}[{WellKnownRegexPatterns.Base62}]{{4}})";
            Signatures = new HashSet<string>([LegacyCaskSignature]);
        }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => [
            new(LegacyCaskSignature,
                MakeHighPerformancePattern(Pattern, LegacyCaskSignature),
                signaturePrefixLength: 52,
                minMatchLength: 84,
                maxMatchLength: 84),
        ];
#endif

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (!LegacyCommonAnnotatedSecurityKey.TryCreate(match, out var legacyCask))
            {
                return null;
            }

            return legacyCask.ProviderFixedSignature == ProviderSignature
                ? base.GetMatchIdAndName(match)
                : null;
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            byte[] providerDataBytes = Convert.FromBase64String(ProviderData);

            bool customerManagedKey = char.IsUpper(ProviderSignature[0]);

            for (int i = 0; i < 62; i++)
            {
                char testChar = CustomAlphabetEncoder.DefaultBase62Alphabet[i];

                string key = null;

                key = IdentifiableSecrets.GenerateCommonAnnotatedTestKey(randomBytes: null,
                                                                         IdentifiableSecrets.VersionTwoChecksumSeed,
                                                                         ProviderSignature,
                                                                         customerManagedKey,
                                                                         platformReserved: null,
                                                                         providerReserved: providerDataBytes,
                                                                         longForm: false,
                                                                         testChar,
                                                                         keyKindSignature: '9');


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
