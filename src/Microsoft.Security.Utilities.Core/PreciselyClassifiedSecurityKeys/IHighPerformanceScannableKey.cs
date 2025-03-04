// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

/// <summary>
/// Interface for keys that can be scanned using <see
/// cref="HighPerformanceScanner"/>. In release builds, it is just a marker
/// interface, but in debug builds it returns data used to generate code.
/// </summary>
internal interface IHighPerformanceScannableKey
{
#if HIGH_PERFORMANCE_CODEGEN
    public IEnumerable<HighPerformancePattern> HighPerformancePatterns { get; }
#endif
}