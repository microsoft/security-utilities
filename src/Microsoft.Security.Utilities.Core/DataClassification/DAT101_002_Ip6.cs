// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Ip6 : RegexPattern
    {
        public Ip6()
        {
            Id = "DAT101/002";
            Name = nameof(Ip6);
            Pattern = @"(?i)^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            var example = "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff";
            yield return example.ToLowerInvariant();
            yield return example.ToUpperInvariant();
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // zero-compression is not handled by this rule
            yield return "3fff::";
        }
    }
}
