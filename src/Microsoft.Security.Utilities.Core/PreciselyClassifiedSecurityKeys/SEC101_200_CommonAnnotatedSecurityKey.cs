﻿// Copyright (c) Microsoft. All rights reserved.
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
            Pattern = $"{WellKnownRegexPatterns.PrefixAllBase64}(?P<secret>[{WellKnownRegexPatterns.Base62}]{{52}}JQQJ9(?:9|D)[{WellKnownRegexPatterns.Base62}][A-L][{WellKnownRegexPatterns.Base62}]{{16}}[A-Za-z][{WellKnownRegexPatterns.Base62}]{{7}}(?:[{WellKnownRegexPatterns.Base62}]{{2}}==)?)";
            Signatures = "JQQJ9".ToSet();
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            int attempts = 0;

            foreach (bool longForm in new[] { true, false })
            {
                while (true) 
                {
                    char testChar = (char)('a' + attempts++);

                    if (testChar == '{')
                    {
                        break;
                    }

                    string example = null;

                    try
                    {
                        foreach (char keyKindSignature in new[]{ '9', 'D', 'H' })
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
                    }
                    catch (InvalidOperationException)
                    {
                        example = null;
                    }

                    if (example == null) { continue; }

                    yield return example;
                }
            }
        }
    }
}
