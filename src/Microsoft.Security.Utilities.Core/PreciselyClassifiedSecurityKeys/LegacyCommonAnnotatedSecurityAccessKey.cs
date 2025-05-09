// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public abstract class LegacyCommonAnnotatedSecurityAccessKey : UnclassifiedLegacyCommonAnnotatedSecurityKey
    {
        abstract protected string ProviderSignature { get; }

        private const string PlatformData = $"[{WellKnownRegexPatterns.Base62}]{{12}}";

        protected string ProviderData { get; }

        protected LegacyCommonAnnotatedSecurityAccessKey(string providerData = "AAAA")
        {
            ProviderData = providerData;
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = $"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>[{WellKnownRegexPatterns.Base62}]{{52}}JQQJ99[{WellKnownRegexPatterns.Base62}][A-L]{PlatformData}{ProviderData}{ProviderSignature}[{WellKnownRegexPatterns.Base62}]{{4}})";
            Signatures = new HashSet<string>([LegacyCaskSignature]);
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
#if DEBUG
            if (!LegacyCommonAnnotatedSecurityKey.TryCreate(match, out var legacyCask))
            {
                return null;
            }
#endif
            if (string.CompareOrdinal(match, LegacyCommonAnnotatedSecurityKey.ProviderFixedSignatureOffset, ProviderSignature, 0, 4) != 0)
            {
                return null;
            }

            if (string.CompareOrdinal(match, LegacyCommonAnnotatedSecurityKey.ProviderReservedOffset, ProviderData, 0, 4) != 0)
            {
                return null;
            }

            if (match[LegacyCommonAnnotatedSecurityKey.StandardFixedSignatureOffset + 5] != '9')
            {
                return null;
            }

            return new Tuple<string, string>(Id, Name);
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
