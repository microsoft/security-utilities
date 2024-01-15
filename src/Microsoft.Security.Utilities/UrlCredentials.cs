// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using static System.Net.WebRequestMethods;

namespace Microsoft.Security.Utilities;

internal sealed class UrlCredentials : RegexPattern
{
    // https://datatracker.ietf.org/doc/html/rfc3986#section-2.3
    private const string UnreservedCharacters = @"[\w\.~\-]";

    // https://datatracker.ietf.org/doc/html/rfc3986#section-2.1
    private const string PercentEncodedCharacters = @"(%|%AZP25)[0-9a-fA-F]{2}";

    // https://datatracker.ietf.org/doc/html/rfc3986#section-2.2
    private const string SubDelimiters = @"[!\$&'\(\)\*\+,;=]";

    private static string Url = $"({UnreservedCharacters}|{PercentEncodedCharacters}|{SubDelimiters}|:)+";

    public UrlCredentials()
    {
        Id = "SEC101/127";

        Name = "UrlCredentials";

        Pattern = $"(?<=//[^:/?#\\n]+:){Url}(?=@)";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        DetectionMetadata = DetectionMetadata.None;

        SniffLiterals = new HashSet<string>(new[]
        {
            "http",
            "https",
        });
    }


    public override IEnumerable<string> GenerateTestExamples()
    {
        // https://tools.ietf.org/html/rfc3986#section-3.2)
        return new[]
        {
            $"http://{Guid.NewGuid()}:{Guid.NewGuid()}@example.com/",
            $"https://user:pass@example.com"
        };
    }
}
