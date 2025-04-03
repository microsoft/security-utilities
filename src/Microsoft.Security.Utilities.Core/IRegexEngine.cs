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
    }
}
