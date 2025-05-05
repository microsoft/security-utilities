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
            Id = "DAT101/001";
            Name = nameof(GuidValue);
            Label = "a GUID";
            Pattern = @"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
        }

        public override Version CreatedVersion => Releases.Version_01_14_00;

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // Example of a GUID, but not a UUID. This example is the Office 365 SharePoint Online App Id. See https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in.
            yield return "00000003-0000-0ff1-ce00-000000000000";

            // Example all lower case.
            yield return "aaaaaaaa-3a2b-41ca-9315-f81f3f566a95";

            // Example with mixed casing.
            yield return "AAAAAAAA-3a2b-41ca-9315-f81f3f566a95";

            yield return Guid.NewGuid().ToString();
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // Example with leading and trailing whitespace to assert the regex is exact and anchored at the start/end.
            yield return " 00000003-0000-0ff1-ce00-000000000000 ";
        }
    }
}
