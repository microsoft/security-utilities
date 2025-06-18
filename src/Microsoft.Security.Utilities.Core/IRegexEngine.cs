// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public interface IRegexEngine
    {
        IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null);

#if NET
        public IEnumerable<UniversalMatch> Matches(ReadOnlySpan<char> input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            throw new NotSupportedException($"Custom regex engine '{GetType().Name}' does not support span input.");
        }
#endif
    }

    internal static class RegexEngineExtensions
    {
        public static IEnumerable<UniversalMatch> Matches(this IRegexEngine engine, StringInput input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
#if NET
            if (input.TryGetString(out string s))
            {
                return engine.Matches(s, pattern, options, timeout, captureGroup);
            }

            return engine.Matches(input.Span, pattern, options, timeout, captureGroup);
#else
            return engine.Matches(input.String, pattern, options, timeout, captureGroup);
#endif
        }
    }
}
