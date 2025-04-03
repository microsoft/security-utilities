// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Float : RegexPattern
    {
        public Float()
        {
            Id = "DAT101/004";
            Name = nameof(Float);
            Label = "a floating point number";
            Pattern = @"^-?(\d+)?\.\d+$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return "0.0";
            yield return "-1.0";
            yield return "-.01";
            yield return "-.1";
            yield return ".1";
            yield return "1.0";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return "12";
            yield return "-1";

            // Localized numbers are not supported.
            yield return "1,0";
        }
    }
}
