// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;

namespace Microsoft.Security.Utilities;

public sealed class Detection
{
    private string? _moniker;

    public Detection(string? id,
                     string? name,
                     string? label,
                     int start,
                     int length,
                     DetectionKind kind,
                     DetectionMetadata metadata,
                     TimeSpan rotationPeriod = default,
                     string? crossCompanyCorrelatingId = null)
    {
        Id = id;
        Name = name;
        Label = label;
        Start = start;
        Length = length;
        Kind = kind;
        Metadata = metadata;
        RotationPeriod = rotationPeriod;
        CrossCompanyCorrelatingId = crossCompanyCorrelatingId;
    }

    /// <summary>
    /// Gets an opaque, stable identifier for the pattern (corresponding to a
    /// SARIF 'reportingDescriptorReference.id' value), e.g., 'SEC101/102'.
    /// </summary>
    public string? Id { get; }

    /// <summary>
    /// Gets a readable pascal-cased name for the detection, e.g., 'AdoPat'.
    /// </summary>
    public string? Name { get; }

    /// <summary>
    /// Gets a user-facing label for the detection, e.g., 'an Azure DevOps
    /// personal access token (PAT).
    /// </summary>
    public string? Label { get; }

    public string Moniker => _moniker ??= $"{Id}.{Name}";

    public int Start { get; }

    public int Length { get; }

    public int End => Start + Length;

    public DetectionKind Kind { get; }

    public DetectionMetadata Metadata { get; }

    public TimeSpan RotationPeriod { get; }

    public string? CrossCompanyCorrelatingId { get; }

#if DEBUG
    public override string ToString()
    {
        return $"{Id}.{Name}:{Start}-{Start + Length}:{Kind}:{Metadata}:{CrossCompanyCorrelatingId}";
    }
#endif
}
