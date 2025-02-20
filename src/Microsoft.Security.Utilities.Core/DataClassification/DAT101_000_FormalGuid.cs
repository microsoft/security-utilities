// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class FormalGuid : RegexPattern
    {
        public FormalGuid()
        {
            Id = "DAT101/000";
            Name = nameof(FormalGuid);
            // This patterns encodes a more formal definition of GUID compared to what might colloquially be thought of as a GUID.
            // Specifically, this GUID ensures there's a 1-5 version identifier in the 3rd block and that the 4th block is constrained to the GUID variant.
            // .NET's System.Guid.Parse will accept more than just this format, but Guid.NewGuid() will always generate a v4 GUID.
            // There are many organic examples of GUIDs that do not meet this strict definition.
            // * 3.5M results on GitHub: https://github.com/search?q=%2F%5B0-9a-f%5D%7B8%7D-%5B0-9a-f%5D%7B4%7D-%5B0-9a-f%5D%7B4%7D-%5B0-9a-f%5D%7B4%7D-%5B0-9a-f%5D%7B12%7D%2F%20NOT%20%2F%5B0-9a-f%5D%7B8%7D-%5B0-9a-f%5D%7B4%7D-%5B1-5%5D%5B0-9a-f%5D%7B3%7D-%5B89ab%5D%5B0-9a-f%5D%7B3%7D-%5B0-9a-f%5D%7B12%7D%2F%20&type=code
            // * Many of the Microsoft-verified first party app ids (e.g.Office 365 SharePoint Online): https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
            Pattern = @"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            var azureCliClientGuid = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
            yield return azureCliClientGuid.ToLowerInvariant();
            yield return azureCliClientGuid.ToUpperInvariant();
            yield return Guid.NewGuid().ToString();
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // Office 365 SharePoint Online - https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
            yield return "00000003-0000-0ff1-ce00-000000000000";
        }
    }
}