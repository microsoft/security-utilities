// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.RE2.Managed;

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public class RE2RegexEngine : IRegexEngine
    {
        public static IRegexEngine Instance = new RE2RegexEngine();

        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions options = RegexOptions.ExplicitCapture | RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan timeout = default, string captureGroup = null)
        {
            foreach (FlexMatch flexMatch in RE2Regex.Instance.Matches(input, pattern, options, timeout, captureGroup))
            {
                yield return new UniversalMatch
                {
                    Index = flexMatch.Index,
                    Length = flexMatch.Length,
                    Value = flexMatch.Value,
                    Success = flexMatch.Success
                };
            }
        }
    }
}
