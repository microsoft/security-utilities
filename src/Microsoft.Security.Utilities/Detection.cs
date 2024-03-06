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
        : this(other?.Id, other?.Name, other?.Start ?? default, other?.Length ?? default, other?.Metadata ?? default, other?.RotationPeriod ?? default, other?.Sha256Hash ?? default, other?.RedactionToken)
    {
        other = other ?? throw new ArgumentNullException(nameof(other));
    }

    public Detection(string? id, string? name, int start, int length, DetectionMetadata metadata, TimeSpan rotationPeriod = default, string? sha256Hash = null, string? token = DefaultRedactionToken)
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

    public string? Sha256Hash { get; set; }

    public string? SecureCorrelationHash => CreateSecureCorrelationHash();

    private string? secureCorrelationHash;

    private string? CreateSecureCorrelationHash()
    {
        if (Sha256Hash == null)
        {
            return null;
        }

        if (secureCorrelationHash == null)
        {
            string correlationHash = $"CrossMicrosoftCorrelatingId:{Sha256Hash}";
            secureCorrelationHash = RegexPattern.GenerateSha256Hash(correlationHash).Substring(0, 32);
        }

        return secureCorrelationHash;
    }

    private string? m_redactionToken;

    public string RedactionToken
    {
        get
        {
            return m_redactionToken ?? DefaultRedactionToken;
        }
        set
        {
            m_redactionToken = value;
        }
    }

    public bool Equals(Detection other)
    {
        if (object.Equals(other, null))
        {
            return false;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(Name, other.Name, StringComparison.Ordinal)
            && string.Equals(Sha256Hash, other.Sha256Hash, StringComparison.Ordinal)
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

    public const string DefaultRedactionToken = "***";

#if DEBUG
    public override string ToString()
    {
        return $"{Id}.{Name}:{Start}-{Start + Length}:{Metadata}:{Sha256Hash}:{RedactionToken}";
    }
#endif
}
