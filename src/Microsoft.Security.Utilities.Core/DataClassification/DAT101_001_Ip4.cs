// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class Ip4 : RegexPattern
    {
        public Ip4()
        {
            Id = "DAT101/001";
            Name = nameof(Ip4);
            Pattern = @"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return "127.0.0.1";
            yield return "255.255.255.255";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return "999.0.0.1";
            yield return "010.0.0.1";
        }
    }
}