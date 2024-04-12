// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.RegularExpressions;

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
        Pattern = $@"^[{WellKnownRegexPatterns.Hexadecimal}]{{32}}$";
        
        DetectionMetadata = DetectionMetadata.HighEntropy;
    }

    public override Tuple<string, string>? GetMatchIdAndName(string match) => new Tuple<string, string>("SEC000/001", "Unclassified64ByteBase64String");

    public override IEnumerable<string> GenerateTestExamples()
    {
        yield return $"{WellKnownRegexPatterns.RandomHexadecimal(32)}";
    }
}