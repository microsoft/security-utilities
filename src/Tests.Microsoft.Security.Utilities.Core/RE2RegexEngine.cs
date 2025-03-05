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

#if NET7_0_OR_GREATER
        public const RegexOptions RegexOptionsDefaults = RegexOptions.ExplicitCapture | RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;
#else
        public const RegexOptions RegexOptionsDefaults = RegexOptions.ExplicitCapture | RegexOptions.Compiled | RegexOptions.CultureInvariant;
#endif
        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions options = RegexOptionsDefaults, TimeSpan timeout = default, string captureGroup = null)
        {
            if (captureGroup == null)
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
            else
            {
                // This value is to set a limit on memory used for its (deterministic) DFA caching.
                // When a specific regex evaluation exceeds this limit, the regex engine will
                // fall back to a non-deterministic approach with some unmeasured perf impact.
                int maxMemoryInBytes = 256 * 1024 * 1024; // 256MB
                if (Regex2.Matches(pattern, input, out List<Dictionary<string, FlexMatch>> matches, maxMemoryInBytes))
                {
                    foreach (Dictionary<string, FlexMatch> match in matches)
                    {
                        FlexMatch flexMatch = match["0"];
                        if (match.TryGetValue(captureGroup, out FlexMatch refineMatch))
                        {
                            flexMatch = refineMatch;
                        }

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
    }
}
