// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class OAuth2BearerToken : RegexPattern
    {
        public OAuth2BearerToken()
        {
            Id = "SEC101/061";
            Name = nameof(OAuth2BearerToken);
            DetectionMetadata = DetectionMetadata.LowConfidence;

            // https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
            Pattern = @$"(?i)authorization:(\s|%20)bearer(\s|%20)(?P<refine>[0-9a-z][{WellKnownRegexPatterns.UrlUnreserved}+\/=]*)([^{WellKnownRegexPatterns.UrlUnreserved}+/=]|$)";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"Authorization: bearer notasecret==";
            yield return $"authorization:%20bearer%20secretplacholder";
        }
    }
}