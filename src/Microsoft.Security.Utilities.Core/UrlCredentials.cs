﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public sealed class UrlCredentials : RegexPattern
{
    public UrlCredentials()
    {
        Id = "SEC101/127";

        Name = nameof(UrlCredentials);

        Pattern = @"(ftps?|https?):\/\/(?:[^:@]+):(?<refine>[^:@?]+)@";

        DetectionMetadata = DetectionMetadata.MediumConfidence;

        Signatures = new HashSet<string>(new[]
        {
            "ftp",
            "http"
        });
    }

    public override Tuple<string, string> GetMatchIdAndName(string match)
    {
        return base.GetMatchIdAndName(match);
    }

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        // https://tools.ietf.org/html/rfc3986#section-3.2)
        return new[]
        {
            $"http://{Guid.NewGuid()}:{Guid.NewGuid()}@example.com/",
            $"https://user:pass@example.com"
        };
    }
}
