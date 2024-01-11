// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    /// A private class used to capture data for test cases.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class TestCase
    {
        /// <summary>
        /// Gets or sets the 64-bit seed that is passed to the Marvin checksum algorithm.
        /// </summary>
        public ulong Seed { get; set; }

        /// <summary>
        /// Gets or sets the text input to the checksum algorithm.
        /// </summary>
        public string Text { get; set; }

        /// <summary>
        /// Gets or sets the expected checksum value of the text input.
        /// </summary>
        public ulong Checksum { get; set; }
    }
}
