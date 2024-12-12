// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class CommonAnnotatedSecurityKey : RegexPattern
    {
        public CommonAnnotatedSecurityKey()
        {
            Id = "SEC101/200";
            Name = nameof(CommonAnnotatedSecurityKey);
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = $"{WellKnownRegexPatterns.PrefixBase62}(?P<secret>[{WellKnownRegexPatterns.Base62}]{{52}}JQQJ9(?:9|D|H)[{WellKnownRegexPatterns.Base62}][A-L][{WellKnownRegexPatterns.Base62}]{{16}}[A-Za-z][{WellKnownRegexPatterns.Base62}]{{7}}(?:[{WellKnownRegexPatterns.Base62}]{{2}}==)?)";
            Signatures = "JQQJ9".ToSet();
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            foreach (bool longForm in new[] { true, false })
            {
                for (int i = 0; i < 62; i++)
                {
                    char testChar = CustomAlphabetEncoder.DefaultBase62Alphabet[i];

                    string example = null;

                    foreach (char keyKindSignature in new[] { '9', 'D', 'H' })
                    {
                        example = IdentifiableSecrets.GenerateCommonAnnotatedTestKey(randomBytes: null,
                                                                                     IdentifiableSecrets.VersionTwoChecksumSeed,
                                                                                     "TEST",
                                                                                     customerManagedKey: true,
                                                                                     platformReserved: null,
                                                                                     providerReserved: null,
                                                                                     longForm,
                                                                                     testChar,
                                                                                     keyKindSignature);
                    }

                    yield return example;
                }
            }
        }
    }
}
