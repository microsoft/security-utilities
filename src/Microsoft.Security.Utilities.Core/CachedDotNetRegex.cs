// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    ///  CachedDotNetRegex is an IRegex implementation which pre-compiles all Regexes and then
    ///  calls through to .NET's System.Text.RegularExpressions.Regex.
    /// </summary>
    public class CachedDotNetRegex : IRegexEngine
    {
        public static IRegexEngine Instance = new CachedDotNetRegex();

        internal static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        private CachedDotNetRegex()
        {
        }

        internal static ConcurrentDictionary<(string Pattern, RegexOptions Options), Regex> RegexCache { get; } = new();

        public static Regex GetOrCreateRegex(string pattern, RegexOptions options)
        {
            var key = (pattern, options);
#if NET7_0_OR_GREATER
            return RegexCache.GetOrAdd(key, key => new Regex(key.Pattern, key.Options | RegexOptions.Compiled | RegexOptions.NonBacktracking));
#else
            return RegexCache.GetOrAdd(key, key => new Regex(key.Pattern, key.Options | RegexOptions.Compiled));
#endif
        }

        public bool IsMatch(string input, string pattern, RegexOptions options = RegexDefaults.DefaultOptionsCaseSensitive, TimeSpan timeout = default, string captureGroup = null)
        {
            // Note: Instance Regex.IsMatch has no timeout overload.
            Regex regex = GetOrCreateRegex(pattern, options);
            Match match = regex.Match(input);
            return match.Success && (captureGroup == null || match.Groups[captureGroup].Success);
        }

        public UniversalMatch Match(string input, string pattern, RegexOptions options = RegexDefaults.DefaultOptionsCaseSensitive, TimeSpan timeout = default, string captureGroup = null)
        {
            // Note: Instance Regex.Match has no timeout overload.
            Regex regex = GetOrCreateRegex(pattern, options);
            return ToFlex(regex.Match(input), captureGroup);
        }

        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions options = RegexDefaults.DefaultOptionsCaseSensitive, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            Regex regex = GetOrCreateRegex(pattern, options);
            foreach (Match m in regex.Matches(input))
            {
                yield return ToFlex(m, captureGroup);

                // Instance Regex.Matches has no overload; check timeout between matches
                // (MatchesCollection *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }
        }

        public bool Matches(string pattern, string text, out List<Dictionary<string, UniversalMatch>> matches, long maxMemoryInBytes = -1)
        {
            matches = new List<Dictionary<string, UniversalMatch>>();

            Regex regex = GetOrCreateRegex(pattern, RegexOptions.None);

            foreach (Match m in regex.Matches(text))
            {
                var current = new Dictionary<string, UniversalMatch>(m.Groups.Count);
                foreach (string groupName in regex.GetGroupNames())
                {
                    Group group = m.Groups[groupName];
                    current.Add(groupName, new UniversalMatch { Success = group.Success, Index = group.Index, Value = group.Value, Length = group.Length });
                }

                matches.Add(current);
            }

            return matches.Count > 0;
        }

        internal static UniversalMatch ToFlex(Match match, string captureGroup = null)
        {
            int index = match.Index;
            int length = match.Length;
            string value = match.Value;

            if (captureGroup != null)
            {
                Group group = match.Groups[captureGroup];
                if (group.Success)
                {
                    value = group.Value;
                    index = group.Index;
                    length = group.Length;
                }
            }

            return new UniversalMatch() { Success = match.Success, Index = index, Length = length, Value = value };
        }
    }
}
