// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1600  // Elements should be documented.


internal sealed class Unclassified32ByteBase64String : RegexPattern
{
    private Azure32ByteIdentifiableKeys azure32ByteIdentifiableKeys = new Azure32ByteIdentifiableKeys();

    public Unclassified32ByteBase64String()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownRegexPatterns.Base64}]{{43}}=)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        DetectionMetadata = DetectionMetadata.HighEntropy;
    }

    public override (string id, string name)? GetMatchIdAndName(string match) => ("SEC101/101", "Unclassified32ByteBase64String");

    public override IEnumerable<string> GenerateTestExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomBase64(43)}=";
    }

    public override IEnumerable<Detection> GetDetections(string input, bool generateSha256Hashes)
    {
        foreach (Detection detection in base.GetDetections(input, generateSha256Hashes))
        {
            string match = input.Substring(detection.Start, detection.Length);
            if (!object.Equals(azure32ByteIdentifiableKeys.GetDetections(match, generateSha256Hashes).FirstOrDefault(), default))
            {
                continue;
            }

            yield return detection;
        }
    }
}
