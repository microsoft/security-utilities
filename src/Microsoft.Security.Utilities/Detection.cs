// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Security.Utilities;

internal struct Detection : IEquatable<Detection>
{
    public Detection(string id, string name, int start, int length, DetectionMetadata metadata, TimeSpan rotationPeriod, string? sha256Hash = null, string token = DefaultRedactionToken)
    {
        Id = id;
        Name = name;
        Start = start;
        Length = length;
        Metadata = metadata;
        Sha256Hash = sha256Hash;
        m_redactionToken = token;
        RotationPeriod = rotationPeriod;
    }

    /// <summary>
    /// Gets or sets an opaque, stable identifier for the pattern (corresponding to a SARIF 'reportingDescriptorReference.id' value).
    /// </summary>
    public string Id { get; set; }

    /// <summary>
    /// Gets or sets a readable name for the detection.
    /// </summary>
    public string Name { get; set; }

    public readonly string Moniker => $"{Id}.{Name}";

    public int Start { get; set; }

    public int Length { get; set; }

    public readonly int End => Start + Length;

    public DetectionMetadata Metadata { get; set; }

    public TimeSpan RotationPeriod { get; set; }

    public string? Sha256Hash { get; set; }

    private string? m_redactionToken;

    public readonly string RedactionToken => m_redactionToken ?? DefaultRedactionToken;

    public readonly bool Equals(Detection other)
    {
        // RotationPeriod is consciously excluded from this computation.
        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Name, other.Name, StringComparison.Ordinal)
            && string.Equals(Sha256Hash, other.Sha256Hash, StringComparison.Ordinal)
            && string.Equals(RedactionToken, other.RedactionToken, StringComparison.Ordinal)
            && Metadata.Equals(other.Metadata)
            && int.Equals(Start, other.Start)
            && int.Equals(Length, other.Length);
    }

    /// <inheritdoc/>
    public override readonly bool Equals(object? obj)
    {
        if (obj is Detection detection)
        {
            return Equals(detection);
        }

        return false;
    }

    public override readonly int GetHashCode()
    {
        int hashCode = 17;

        // RotationPeriod is consciously excluded from this computation.
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

            if (Sha256Hash != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + Sha256Hash.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + Sha256Hash.GetHashCode();
#endif
            }

            if (m_redactionToken != null)
            {
#if NET5_0_OR_GREATER
                hashCode = (hashCode * 31) + m_redactionToken.GetHashCode(StringComparison.Ordinal);
#else
                hashCode = (hashCode * 31) + m_redactionToken.GetHashCode();
#endif
            }

            hashCode = (hashCode * 31) + Start.GetHashCode();
            hashCode = (hashCode * 31) + Length.GetHashCode();
            hashCode = (hashCode * 31) + Metadata.GetHashCode();
        }

        return hashCode;
    }

    public static bool operator ==(Detection left, Detection right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(Detection left, Detection right)
    {
        return !(left == right);
    }

    public const string DefaultRedactionToken = "***";

    public override readonly string ToString()
    {
        return $"{Id}.{Name}:{Start}-{Start + Length}:{Metadata}:{Sha256Hash}:{RedactionToken}";
    }
}
