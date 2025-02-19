// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class GuidValue : RegexPattern
    {
        public GuidValue()
        {
            Id = "SEC001/000";
            Name = nameof(GuidValue);
            Pattern = @"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // TODO(rosswollman): The test harness does not have a formal way to name test cases and debug specific test cases. (e.g. what Theory or other data driven tests would provide out of the box.)
            // Test Case Name: MixedCaseAndAlphaNumerics
            yield return "12Aa0000-0Cd0-00eF-cB00-eF0000000000";
            yield return Guid.NewGuid().ToString();
        }

        // TODO(rosswollman): The repo does not have tests for True Negatives.
        //                    This could lead to a lot of incorrect classifications.
    }
}