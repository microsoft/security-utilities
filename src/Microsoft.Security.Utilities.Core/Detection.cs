// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;

namespace Microsoft.Security.Utilities;

public class Detection : IEquatable<Detection>
{
    public Detection()
    {
    }

    public Detection(Detection other)
        : this(other?.Id, other?.Name, other?.Start ?? default, other?.Length ?? default, other?.Metadata ?? default, other?.RotationPeriod ?? default, other?.CrossCompanyCorrelatingId ?? default, other?.RedactionToken ?? default)
    {
        other = other ?? throw new ArgumentNullException(nameof(other));
    }

    public Detection(string? id, string? name, int start, int length, DetectionMetadata metadata, TimeSpan rotationPeriod = default, string? crossCompanyCorrelatingId = null, string? redactionToken = null)
    {
        Id = id;
        Name = name;
        Start = start;
        Length = length;
        Metadata = metadata;
        RedactionToken = redactionToken;
        RotationPeriod = rotationPeriod;
        CrossCompanyCorrelatingId = crossCompanyCorrelatingId;
    }

    /// <summary>
    /// Gets or sets an opaque, stable identifier for the pattern (corresponding to a SARIF 'reportingDescriptorReference.id' value).
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets a readable name for the detection.
    /// </summary>
    public string? Name { get; set; }

    public string Moniker => $"{Id}.{Name}";

    public int Start { get; set; }

    public int Length { get; set; }

    public int End => Start + Length;

    public DetectionMetadata Metadata { get; set; }

    public TimeSpan RotationPeriod { get; set; }

    public string? CrossCompanyCorrelatingId { get; set; }

    public virtual string? RedactionToken { get; set; }

    public bool Equals(Detection? other)
    {
        if (object.Equals(other, null))
        {
            return false;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Name, other.Name, StringComparison.Ordinal)
            && string.Equals(CrossCompanyCorrelatingId, other.CrossCompanyCorrelatingId, StringComparison.Ordinal)
            && string.Equals(RedactionToken, other.RedactionToken, StringComparison.Ordinal)
            && Metadata.Equals(other.Metadata)
            && int.Equals(Start, other.Start)
            && int.Equals(Length, other.Length)
            && TimeSpan.Equals(RotationPeriod, other.RotationPeriod);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        if (obj is Detection detection)
        {
            return Equals(detection);
        }

        return false;
    }

    public override int GetHashCode()
    {
        int hashCode = 17;

        unchecked
        {
            if (Id != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + Id.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + Id.GetHashCode();
#endif

            }

            if (Name != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + Name.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + Name.GetHashCode();
#endif
            }

            if (CrossCompanyCorrelatingId != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + CrossCompanyCorrelatingId.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + CrossCompanyCorrelatingId.GetHashCode();
#endif
            }

            if (RedactionToken != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + RedactionToken.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + RedactionToken.GetHashCode();
#endif
            }

            hashCode = (hashCode * 31) + Start.GetHashCode();
            hashCode = (hashCode * 31) + Length.GetHashCode();
            hashCode = (hashCode * 31) + Metadata.GetHashCode();
            hashCode = (hashCode * 31) + RotationPeriod.GetHashCode();
        }

        return hashCode;
    }

    public static bool operator ==(Detection left, Detection right)
    {
        if (object.Equals(left, null))
        {
            return object.Equals(right, null);
        }

        return left.Equals(right);
    }

    public static bool operator !=(Detection left, Detection right)
    {
        return !(left == right);
    }


#if DEBUG
    public override string ToString()
    {
        return $"{Id}.{Name}:{Start}-{Start + Length}:{Metadata}:{CrossCompanyCorrelatingId}:{RedactionToken}";
    }
#endif
}
