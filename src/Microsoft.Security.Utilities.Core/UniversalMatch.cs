// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    /// <summary>
    ///  UniversalMatch is a generic subset of System.Text.RegularExpressions.Match.
    /// </summary>
    public class UniversalMatch
    {
        public bool Success { get; set; }

        public int Index { get; set; }

        public int Length { get; set; }

        public string Value { get; set; }
    }
}
