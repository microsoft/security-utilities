// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Web;

namespace Microsoft.Security.Utilities
{
    public class LooseSasSecret : RegexPattern
    {
        public LooseSasSecret()
        {
            Id = "SEC101/060";
            Name = nameof(LooseSasSecret);
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.MediumConfidence;
            Pattern = @$"(?i)(?:^|[?;&])(?:dsas_secret|sig)=(?P<refine>[0-9a-z\/+%]{{43,129}}(?:=|%3d))";
            Signatures = new HashSet<string>(new[] { "sig=", "ret=" });
        }


        // HttpUtility.UrlEncode(new string('/', 43));
        private const string FortyThreeBase64EncodedSlashes = "%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f";

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"dsas_secret={WellKnownRegexPatterns.RandomBase64(43)}=";
            yield return $"sig={WellKnownRegexPatterns.RandomBase64(43)}%3d";

            // A pathological example where the base64 encoded signature comprises nothing
            // but forward slashes or plus signs. This extremely unlikely case accounts for
            // the upper bound of 129 characters in the pattern.
            yield return @$"dsas_secret={FortyThreeBase64EncodedSlashes}%3D";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            yield return $"dsas_secret={WellKnownRegexPatterns.RandomBase64(43)}";
            yield return $"sig={WellKnownRegexPatterns.RandomBase64(43)}";

            // No trailing padding.
            yield return @$"dsas_secret={FortyThreeBase64EncodedSlashes}";

            // Exceeds length limit in regex.
            yield return @$"dsas_secret={FortyThreeBase64EncodedSlashes}%2f%3D";
        }
    }
}