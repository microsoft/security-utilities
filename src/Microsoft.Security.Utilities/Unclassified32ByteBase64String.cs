// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

#pragma warning disable CA1055  // Change the return type of method from 'string' to 'System.Uri'.
#pragma warning disable CPR139  // Regular expressions should be reused from static fields of properties
#pragma warning disable CS1591  // Missing XML comment for publicly visible type or member.
#pragma warning disable IDE1006 // Naming rule violation.
#pragma warning disable R9A014  // Using R9 ThrowsIfNull.
#pragma warning disable R9A015  // Use R9 ArgumentOutOfRangeException helper.
#pragma warning disable R9A044  // Assign array of literal values to static field for improved performance.
#pragma warning disable R9A049  // Newly added symbol must be marked as experimental.
#pragma warning disable S109    // Assign this magic number to a variable or constant.
#pragma warning disable S1067
#pragma warning disable S3995   // Convert this return type to 'System.Uri'.
#pragma warning disable S125    // Remove uncommented code.
#pragma warning disable S2328
#pragma warning disable SA1204  // Static members should appear before non-static members.
#pragma warning disable SA1600  // Elements should be documented.
#pragma warning disable SA1602  // Enumeration items should be documented.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.


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
