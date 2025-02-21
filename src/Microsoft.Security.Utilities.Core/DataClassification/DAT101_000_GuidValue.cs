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
            Id = "DAT101/000";
            Name = nameof(GuidValue);
            Pattern = @"(?i)^([0-9a-f]{8}-[0-9a-f]{4}-[0|9|a|b|c|d|e|f][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12})" +
                       "|([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[^89ab][0-9a-f]{3}-[0-9a-f]{12})$";
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (UuidValue.c_Nil.Equals(match, StringComparison.OrdinalIgnoreCase) || UuidValue.c_Max.Equals(match, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // Example of a GUID, but not a UUID. This example is the Office 365 SharePoint Online App Id. See https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in.
            yield return "00000003-0000-0ff1-ce00-000000000000";

            // Example of almost a UUIDv4, but the first 'c' of the 4th block ('cbac') makes it not a UUID, but a GUID.
            yield return "919108f7-52d1-4320-cbac-f847db4148a8";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // Example of a UUIDv4 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv4-value.
            yield return "919108f7-52d1-4320-9bac-f847db4148a8";

            yield return UuidValue.c_Nil;
            yield return UuidValue.c_Max; 
        }
    }
}
