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
            Id = "SEC101/051";
            Name = nameof(LooseSasSecret);
            DetectionMetadata = DetectionMetadata.HighEntropy;
            Pattern = @$"(?i)(?:^|[?;&])(?:dsas_secret|sig)=(?<refine>[0-9a-z\/+%]{{43,}}(?:=|%3d))";
            Signatures = new HashSet<string>(new[] { "sig=", "ret=" });
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"dsas_secret={WellKnownRegexPatterns.RandomBase64(43)}=";
            yield return $"sig={WellKnownRegexPatterns.RandomBase64(43)}%3d";
            yield return @$"dsas_secret={HttpUtility.UrlEncode(new string('/', 43))}%3D";
        }
    }
}