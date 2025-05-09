// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Security.Utilities;

#nullable enable
#pragma warning disable SA1600  // Elements should be documented.

[ExcludeFromCodeCoverage]
internal sealed class Unclassified16ByteHexadecimalString : RegexPattern
{
    public Unclassified16ByteHexadecimalString()
    {
        Id = "SEC000/002";
        Name = nameof(Unclassified16ByteHexadecimalString);
        Label = "an unclassified 16-byte hexadecimal string";
        Pattern = $@"{WellKnownRegexPatterns.PrefixHexadecimal}[{WellKnownRegexPatterns.Hexadecimal}]{{32}}{WellKnownRegexPatterns.SuffixHexadecimal}";
        DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.Unclassified | DetectionMetadata.LowConfidence;
    }

    public override Version CreatedVersion => Releases.Version_01_04_12;

    public override Tuple<string, string>? GetMatchIdAndName(string match) => new Tuple<string, string>("SEC000/002", nameof(Unclassified16ByteHexadecimalString));

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomHexadecimal(32)}";
    }
}
