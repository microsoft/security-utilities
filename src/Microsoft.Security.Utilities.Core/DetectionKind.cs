// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

namespace Microsoft.Security.Utilities;

public enum DetectionKind
{
    /// <summary>
    /// Detected by literal value.
    /// </summary>
    Literal = 0,

    /// <summary>
    /// Detected by regular expression.
    /// </summary>
    Regex = 1,
}
