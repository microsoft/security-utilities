// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    internal static class RegexDefaults
    {
#if NET7_0_OR_GREATER
        public static RegexOptions DefaultOptions { get; } = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture | RegexOptions.NonBacktracking;
#else
        public static RegexOptions DefaultOptions { get; } = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;
#endif
    }
}