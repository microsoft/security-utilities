// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities;
#nullable enable
#pragma warning disable SA1600  // Elements should be documented.

internal sealed class Unclassified32ByteBase64String : RegexPattern
{
    private Azure32ByteIdentifiableKeys azure32ByteIdentifiableKeys = new Azure32ByteIdentifiableKeys();

    public Unclassified32ByteBase64String()
    {
        Id = "SEC000/000";
        Name = nameof(Unclassified32ByteBase64String);
        Label = "an unclassified 32-byte base64 string";
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}[{WellKnownRegexPatterns.Base64}]{{43}}=";
        DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.Unclassified | DetectionMetadata.LowConfidence;
    }

    public override Version CreatedVersion => Releases.Version_01_04_12;

    public override Tuple<string, string>? GetMatchIdAndName(string match) => new Tuple<string, string>("SEC000/000", "Unclassified32ByteBase64String");

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomBase64(43)}=";
    }

    internal override IEnumerable<Detection> GetDetections(StringInput input,
                                                           bool generateCrossCompanyCorrelatingIds,
                                                           string defaultRedactionToken = RegexPattern.FallbackRedactionToken,
                                                           IRegexEngine? regexEngine = null)
    {
        foreach (Detection detection in base.GetDetections(input, generateCrossCompanyCorrelatingIds, defaultRedactionToken, regexEngine))
        {
            string match = input.Substring(detection.Start, detection.Length);

            if (azure32ByteIdentifiableKeys.GetDetections(match,
                                                          generateCrossCompanyCorrelatingIds: false,
                                                          defaultRedactionToken,
                                                          regexEngine).Any())
            {
                continue;
            }

            yield return detection;
        }
    }
}
