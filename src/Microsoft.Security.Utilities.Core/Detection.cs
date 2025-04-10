// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Diagnostics;

namespace Microsoft.Security.Utilities;

public sealed class Detection
{
    private string? _moniker;

    public Detection(string? id,
                     string? name, 
                     string? label,
                     int start,
                     int length,
                     DetectionMetadata metadata,
                     TimeSpan rotationPeriod = default, 
                     string? crossCompanyCorrelatingId = null, 
                     string? redactionToken = null)
    {
        Id = id;
        Name = name;
        Label = label;
        Start = start;
        Length = length;
        Metadata = metadata;
        RedactionToken = redactionToken;
        RotationPeriod = rotationPeriod;
        CrossCompanyCorrelatingId = crossCompanyCorrelatingId;
    }

    /// <summary>
    /// Gets or sets an opaque, stable identifier for the pattern (corresponding
    /// to a SARIF 'reportingDescriptorReference.id' value), e.g., 'SEC101/102'.
    /// </summary>
    public string? Id { get; }

    /// <summary>
    /// Gets or sets a readable pascal-cased name for the detection, e.g., 'AdoPat'.
    /// </summary>
    public string? Name { get; }

    /// <summary>
    /// Gets or sets a user-facing label for the detection, e.g., 'an Azure
    /// DevOps personal access token (PAT).
    /// </summary>
    public string? Label { get; }

    public string Moniker => _moniker ??= $"{Id}.{Name}";

    public int Start { get; }

    public int Length { get; }

    public int End => Start + Length;

    public DetectionMetadata Metadata { get; }

    public TimeSpan RotationPeriod { get; }

    public string? CrossCompanyCorrelatingId { get; }

    public string? RedactionToken { get; }
#if DEBUG
    public override string ToString()
    {
        return $"{Id}.{Name}:{Start}-{Start + Length}:{Metadata}:{CrossCompanyCorrelatingId}:{RedactionToken}";
    }
#endif
}
