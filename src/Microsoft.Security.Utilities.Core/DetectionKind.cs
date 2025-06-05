// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities;

/// <summary>
/// Indicates whether a detection was made using a literal value or a regex.
/// </summary>
public enum DetectionKind
{
    // NOTE: The underlying numeric value is used to sort detections for
    // masking. Higher values sort before lower value. It is important that
    // literal detections are prioritized over regex detections by masking, so
    // the underlying value for 'Literal' here must be greater than the value
    // for 'Regex'. 'Regex' is also given the default zero value because regex
    // detection construction occurs in multiple places while literal detection
    // occurs in just one.

    /// <summary>
    /// Detected by regular expression.
    /// </summary>
    /// <remarks>
    /// </remarks>
    Regex = 0,

    /// <summary>
    /// Detected by literal value.
    /// </summary>
    Literal = 1,
}
