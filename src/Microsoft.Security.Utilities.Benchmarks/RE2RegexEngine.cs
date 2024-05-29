// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.RE2.Managed;

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
        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions options = RegexOptionsDefaults, TimeSpan timeout = default, string? captureGroup = null)
        {
            foreach (FlexMatch flexMatch in RE2Regex.Instance.Matches(input, pattern, options, timeout, captureGroup))
            {
                if (captureGroup != null)
                {
                    yield return CachedDotNetRegex.Instance.Matches(input, pattern, options, timeout, captureGroup).First();
                }
                else
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
}
