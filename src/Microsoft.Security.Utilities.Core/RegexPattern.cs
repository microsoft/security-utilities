// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

[DataContract]
public class RegexPattern
{
    public const string FallbackRedactionToken = "+++";

    /// <summary>Constructs a new instance of the RegexPattern class.</summary>
    /// <param name="id"> The unique identifier for the pattern.</param>
    /// <param name="name">The name of the pattern.</param>
    /// <param name="label">A sentence fragment that describes the secret kind.</param>
    /// <param name="pattern">The regular expression pattern.</param>
    /// <param name="patternMetadata">Metadata that describes the pattern.</param>
    /// <param name="rotationPeriod">The period after which a matching secret should be rotated.</param>
    /// <param name="signatures">The set of signatures. The regex is not run if none of them appear in the input.</param>
    /// <param name="regexOptions">Regular expression options to use. If null, use <see cref="RegexDefaults.DefaultOptions"/></param>
    /// <param name="sampleGenerator">A function that generates sample true positives for the pattern. Used by <see cref="GenerateTruePositiveExamples"/></param>
    public RegexPattern(string id,
                        string name,
                        string label,
                        DetectionMetadata patternMetadata,
                        string pattern,
                        TimeSpan rotationPeriod = default,
                        ISet<string>? signatures = null,
                        RegexOptions? regexOptions = null,
                        Func<string[]>? sampleGenerator = null)
    {
        Pattern = pattern ?? throw new ArgumentNullException(nameof(pattern));

        Id = id;
        Name = name;
        Label = label;
        DetectionMetadata = patternMetadata;
        RotationPeriod = rotationPeriod;
        Signatures = signatures;
        RegexOptions = regexOptions ?? RegexDefaults.DefaultOptions;
        m_sampleGenerator = sampleGenerator;
    }

#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor.
    protected RegexPattern()
    {
        RegexOptions = RegexDefaults.DefaultOptions;
    }
#pragma warning restore CS8618

    [ExcludeFromCodeCoverage]
    public override bool Equals(object? obj)
    {
        var item = obj as RegexPattern;
        if (item == null)
        {
            return false;
        }

        if (!string.Equals(Id, item.Id, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(Name, item.Name, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.Equals(Pattern, item.Pattern, StringComparison.Ordinal) ||
            RegexOptions != item.RegexOptions)
        {
            return false;
        }

        if (DetectionMetadata != item.DetectionMetadata)
        {
            return false;
        }

        if (RotationPeriod != item.RotationPeriod)
        {
            return false;
        }

        if (object.Equals(Signatures, item.Signatures))
        {
            return true;
        }

        if (Signatures == null ||
            item.Signatures == null ||
            Signatures.Count != item.Signatures.Count)
        {
            return false;
        }

        foreach (string sniffLiteral in Signatures)
        {
            if (!item.Signatures.Contains(sniffLiteral))
            {
                return false;
            }
        }

        return true;
    }

    public override int GetHashCode()
    {
        int result = 17;
        unchecked
        {
#if NET50_OR_GREATER
            result = (result * 31) + Pattern.GetHashCode(StringComparison.Ordinal);

            if (Id != null)
            {
                result = (result * 31) + Id.GetHashCode(StringComparison.Ordinal);
            }

            if (Name != null)
            {
                result = (result * 31) + Name.GetHashCode(StringComparison.Ordinal);
            }

            result = (result * 31) + m_regexOptions.GetHashCode(StringComparison.Ordinal);
            result = (result * 31) + RotationPeriod.GetHashCode(StringComparison.Ordinal);
            result = (result * 31) + DetectionMetadata.GetHashCode(StringComparison.Ordinal);
#else
            result = (result * 31) + Pattern.GetHashCode();

            if (Id != null)
            {
                result = (result * 31) + Id.GetHashCode();
            }

            if (Name != null)
            {
                result = (result * 31) + Name.GetHashCode();
            }

            result = (result * 31) + RegexOptions.GetHashCode();
            result = (result * 31) + RotationPeriod.GetHashCode();
            result = (result * 31) + DetectionMetadata.GetHashCode();
#endif

            // Use xor for set values to be order-independent.
            if (Signatures != null)
            {
                int xor_0 = 0;
                foreach (var sniffLiteral in Signatures)
                {
#if NET5_0_OR_GREATER
                    xor_0 ^= sniffLiteral.GetHashCode(StringComparison.Ordinal);
#else
                    xor_0 ^= sniffLiteral.GetHashCode();
#endif
                }

                result = (result * 31) + xor_0;
            }
        }

        return result;
    }

    public virtual IEnumerable<Detection> GetDetections(string input,
                                                        bool generateCrossCompanyCorrelatingIds,
                                                        string defaultRedactionToken = FallbackRedactionToken,
                                                        IRegexEngine? regexEngine = null)
    {
        if (input == null)
        {
            yield break;
        }

        bool runRegexes = Signatures == null;

        if (Signatures != null)
        {
            foreach (string sniffLiteral in Signatures)
            {
                if (input.IndexOf(sniffLiteral, StringComparison.Ordinal) != -1)
                {
                    runRegexes = true;
                    break;
                }
            }
        }

        if (runRegexes)
        {
            regexEngine ??= CachedDotNetRegex.Instance;

            int startIndex;
            foreach (UniversalMatch match in regexEngine.Matches(input, Pattern, RegexOptions, captureGroup: "refine"))
            {
                startIndex = match.Index + 1;

                string? crossCompanyCorrelatingId =
                    generateCrossCompanyCorrelatingIds && DetectionMetadata.HasFlag(DetectionMetadata.HighEntropy)
                        ? GenerateCrossCompanyCorrelatingId(match.Value)
                        : null;

                string? redactionToken = crossCompanyCorrelatingId != null
                        ? $"{Id}:{crossCompanyCorrelatingId}"
                        : defaultRedactionToken;

                // If the user has provided a null or empty redaction
                // token, we will use the fallback so that redaction
                // is clearly evident in the output.
                if (string.IsNullOrWhiteSpace(redactionToken))
                {
                    redactionToken = FallbackRedactionToken;
                }

                var moniker = GetMatchIdAndName(match.Value);
                if (moniker == default)
                {
                    continue;
                }

                string id = moniker.Item1;
                string name = moniker.Item2;

                yield return new Detection(id,
                                           name,
                                           label: Label,
                                           match.Index,
                                           match.Length,
                                           DetectionMetadata,
                                           RotationPeriod,
                                           crossCompanyCorrelatingId,
                                           redactionToken);
            }

        }
    }

    /// <summary>
    /// Generate test examples that should result in a positive match.
    /// </summary>
    /// <returns></returns>
    public virtual IEnumerable<string> GenerateTruePositiveExamples()
    {
        if (m_sampleGenerator == null)
        {
            yield break;
        }

        foreach (string example in m_sampleGenerator())
        {
            yield return example;
        }
    }

    /// <summary>
    /// Generate test examples that should not result in a positive match.
    /// </summary>
    /// <returns></returns>
    public virtual IEnumerable<string> GenerateFalsePositiveExamples()
    {
        yield break;
    }

    [ThreadStatic]
    private static SHA256? s_sha;

    public static string GenerateCrossCompanyCorrelatingId(string text)
    {
        string hash = RegexPattern.GenerateSha256Hash(text);

        hash = $"CrossMicrosoftCorrelatingId:{hash}";

        s_sha ??= SHA256.Create();
        byte[] byteHash = Encoding.UTF8.GetBytes(hash);
        byte[] checksum = s_sha.ComputeHash(byteHash);

        byte[] toEncode = new byte[15];
        Array.Copy(checksum, 0, toEncode, 0, toEncode.Length);

        return Convert.ToBase64String(toEncode);
    }

    public static string GenerateSha256Hash(string text)
    {
        s_sha ??= SHA256.Create();
        byte[] byteHash = Encoding.UTF8.GetBytes(text);
        byte[] checksum = s_sha.ComputeHash(byteHash);

#if NETCOREAPP3_1_OR_GREATER
        return BitConverter.ToString(checksum).Replace("-", string.Empty, StringComparison.Ordinal);
#else
        return BitConverter.ToString(checksum).Replace("-", string.Empty);
#endif
    }

    public virtual string? GetMatchMoniker(string match)
    {
        Tuple<string, string>? matchIdAndName = GetMatchIdAndName(match);

        return matchIdAndName != null
            ? $"{matchIdAndName!.Item1}.{matchIdAndName!.Item2}"
            : null;
    }

    public virtual Tuple<string, string>? GetMatchIdAndName(string match) => new Tuple<string, string>(Id, Name);

    [DataMember(Order = 5)]
    public string Pattern { get; protected set; }

    /// <summary>
    /// Gets or sets an opaque, stable identifier for the pattern (corresponding to a SARIF 'reportingDescriptorReference.id' value).
    /// </summary>
    [DataMember(Order = 1)]
    public string Id { get; protected set; }

    /// <summary>
    /// Gets or sets a readable name for the detection.
    /// </summary>
    [DataMember(Order = 2)]
    public string Name { get; protected set; }

    /// <summary>
    /// Gets or sets a sentence fragment that comprises the secret kind,
    /// suitable for emitting in user-facing strings, as a label in a
    /// user-interface, etc.
    /// </summary>
    [DataMember(Order = 3)]
    public string Label { get; protected set; }

    [DataMember(Order = 6)]
    public TimeSpan RotationPeriod { get; protected set; }

    /// <summary>
    /// Gets the regular expression options.
    /// </summary>
    /// <remarks>Options may not be available when .NET is not used to
    /// provide regex processing.</remarks>
    public RegexOptions RegexOptions { get; }

    /// <summary>
    /// Gets or sets zero, one or more string literals that must be present in the
    /// input string before the regular expression will be applied.
    /// </summary>
    /// <remarks>
    /// .NET string comparison API are highly optimized. Defining one or
    /// more sniff literals (the presence of which are confirmed by calls
    /// to <see cref = "string.IndexOf(string)"/> may result in better
    /// performance as these calls are typically much faster than
    /// equivalent regular expressions.
    /// </remarks>
    [DataMember(Order = 7)]
    public ISet<string>? Signatures { get; protected set; }

    private readonly Func<string[]>? m_sampleGenerator;

    /// <summary>
    /// Gets or sets a property that describes pattern characteristics such as whether this detection finds high
    /// entropy secrets (that can be hashed for telemetry) or if the secret kind has been obsoleted by a newer format.
    /// </summary>
    /// <remarks>Options may not be available when .NET is not used to
    /// provide regex processing.</remarks>
    [DataMember(Order = 4)]
    public DetectionMetadata DetectionMetadata { get; protected set; }

    public bool ShouldSerializeRotationPeriod() => false;

#if HIGH_PERFORMANCE_CODEGEN
    // TODO: Refactor to eliminate string manipulation: https://github.com/microsoft/security-utilities/issues/151
    /// <summary>
    /// Converts a standard pattern to one that can be used with <see cref="HighPerformanceScanner"/>.
    ///
    /// - Delimiting prefixes and suffixes are stripped.
    /// - Refine capture group is removed. 
    /// - Signature is replaced with a wildcard of the same length so that the pattern can be shared.
    /// - Uppercase, lowercase, and digit character classes are simplified to ranges.
    /// - The pattern is anchored to the start of the input.
    /// <returns>
    /// <summary>
    private protected static string MakeHighPerformancePattern(string pattern, string signature)
    {
        string regexNormalizedSignature = Regex.Escape(signature);

        foreach (var prefix in WellKnownRegexPatterns.AllPrefixes)
        {
            if (pattern.StartsWith(prefix, StringComparison.Ordinal))
            {
                pattern = pattern.Substring(prefix.Length);
                break;
            }
        }

        foreach (var suffix in WellKnownRegexPatterns.AllSuffixes)
        {
            if (pattern.EndsWith(suffix, StringComparison.Ordinal))
            {
                pattern = pattern.Substring(0, pattern.Length - suffix.Length);
                break;
            }
        }

        const string refineStart = "(?P<refine>";
        if (pattern.StartsWith(refineStart))
        {
            pattern = pattern.Substring(refineStart.Length, pattern.Length - refineStart.Length - 1);
        }

        pattern = pattern.Replace(WellKnownRegexPatterns.Uppercase, "A-Z");
        pattern = pattern.Replace(WellKnownRegexPatterns.Lowercase, "a-z");
        pattern = pattern.Replace(WellKnownRegexPatterns.Digit, "0-9");
        pattern = pattern.Replace(regexNormalizedSignature, $".{{{signature.Length}}}");

        return "^" + pattern;
    }
#endif
}