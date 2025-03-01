// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities;

#if HIGH_PERFORMANCE_CODEGEN
/// <summary>
/// Uncompiled version of <see cref="HighPerformancePattern"/>. This type is not
/// used at runtime and not present in release builds.
/// </summary>
internal sealed class HighPerformancePattern
{
    public string Signature { get; }
    public string ScopedRegex { get; set; }
    public int SignaturePrefixLength { get; }
    public int MinMatchLength { get; }
    public int MaxMatchLength { get; }

    public HighPerformancePattern(string signature, string scopedRegex, int signaturePrefixLength, int minMatchLength, int maxMatchLength)
    {
        Signature = signature;
        ScopedRegex = scopedRegex;
        SignaturePrefixLength = signaturePrefixLength;
        MinMatchLength = minMatchLength;
        MaxMatchLength = maxMatchLength;
    }
}
#endif