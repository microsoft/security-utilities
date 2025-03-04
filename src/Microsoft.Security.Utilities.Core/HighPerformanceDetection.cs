// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities;

/// <summary>
/// A detection from <see cref="HighPerformanceScanner"/>.
/// </summary>
internal readonly record struct HighPerformanceDetection
{
    /// <summary>
    /// The signature of the pattern that was detected.
    /// </summary>
    public string Signature { get; }

    /// <summary>
    /// The start index in the input where the pattern was detected.
    /// </summary>
    public int Start { get; }

    /// <summary>
    /// The length of the match that was detected.
    /// </summary>
    public int Length { get; }

    public HighPerformanceDetection(string signature, int start, int length)
    {
        Signature = signature;
        Start = start;
        Length = length;
    }
}
