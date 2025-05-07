// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Microsoft.Security.Utilities;

#nullable enable
#pragma warning disable SA1600  // Elements should be documented.

[ExcludeFromCodeCoverage]
internal sealed class Unclassified64ByteBase64String : RegexPattern
{
    private Azure64ByteIdentifiableKeys azure64ByteIdentifiableKeys = new Azure64ByteIdentifiableKeys();

    public Unclassified64ByteBase64String()
    {
        Id = "SEC000/001";
        Name = nameof(Unclassified64ByteBase64String);
        Label = "an unclassified 64-byte base64 string";
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}[{WellKnownRegexPatterns.Base64}]{{86}}==";
        DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.Unclassified | DetectionMetadata.LowConfidence;
    }

    public override Version CreatedVersion => Releases.Version_01_04_12;

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomBase64(86)}==";
    }

    public override IEnumerable<Detection> GetDetections(string input,
                                                         bool generateSha256Hashes,
                                                         string defaultRedactionToken = RegexPattern.FallbackRedactionToken,
                                                         IRegexEngine? regexEngine = null)
    {
        foreach (Detection detection in base.GetDetections(input, generateSha256Hashes, defaultRedactionToken, regexEngine))
        {
            string match = input.Substring(detection.Start, detection.Length);

            if (!Equals(azure64ByteIdentifiableKeys.GetDetections(match,
                                                                         generateSha256Hashes,
                                                                         defaultRedactionToken,
                                                                         regexEngine).FirstOrDefault(), objB: default))
            {
                continue;
            }

            yield return detection;
        }
    }
}
