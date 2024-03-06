// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.RegularExpressions;

using Microsoft.RE2.Managed;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1600  // Elements should be documented.

[ExcludeFromCodeCoverage]
internal sealed class Unclassified64ByteBase64String : RegexPattern
{
    private Azure64ByteIdentifiableKeys azure64ByteIdentifiableKeys = new Azure64ByteIdentifiableKeys();

    public Unclassified64ByteBase64String()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownRegexPatterns.Base64}]{{86}}==)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        DetectionMetadata = DetectionMetadata.HighEntropy;
    }

    public override (string id, string name)? GetMatchIdAndName(string match) => ("SEC102/102", "Unclassified64ByteBase64String");

    public override IEnumerable<string> GenerateTestExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomBase64(86)}==";
    }

    public override IEnumerable<Detection> GetDetections(string input, bool generateSha256Hashes, IRegex regexEngine = default)
    {
        foreach (Detection detection in base.GetDetections(input, generateSha256Hashes))
        {
            string match = input.Substring(detection.Start, detection.Length);
            if (!object.Equals(azure64ByteIdentifiableKeys.GetDetections(match, generateSha256Hashes).FirstOrDefault(), default))
            {
                continue;
            }

            yield return detection;
        }
    }
}
