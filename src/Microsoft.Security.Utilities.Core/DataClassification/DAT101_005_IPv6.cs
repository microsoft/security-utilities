// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class IPv6 : RegexPattern
    {
        public IPv6()
        {
            Id = "DAT101/005";
            Name = nameof(IPv6);
            Pattern = @"(?i)^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // Example with all lower case.
            yield return "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff";

            // Example with all UPPER case.
            yield return "3FFF:FFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // Zero-compression, while valid, is not covered (yet) by this rule.
            yield return "3fff::";
        }
    }
}
