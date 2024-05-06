// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

public class RegexPattern
{
    public RegexPattern(string id,
                        string name,
                        DetectionMetadata patternMetadata,
                        string pattern,
                        TimeSpan rotationPeriod = default,
                        ISet<string>? sniffLiterals = null,
#if NET7_0_OR_GREATER
                        RegexOptions regexOptions = RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.NonBacktracking,
#else
                        RegexOptions regexOptions = RegexOptions.Compiled | RegexOptions.ExplicitCapture,
#endif
                        Func<string[]>? sampleGenerator = null)
    {
        Pattern = pattern ?? throw new ArgumentNullException(nameof(pattern));

        Id = id;
        Name = name;
        m_regexOptions = regexOptions;
        SniffLiterals = sniffLiterals;
        RotationPeriod = rotationPeriod;
        m_sampleGenerator = sampleGenerator;
        DetectionMetadata = patternMetadata;
    }

#pragma warning disable CS8618
    protected RegexPattern()
    {
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
            m_regexOptions != item.m_regexOptions)
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

        if (object.Equals(SniffLiterals, item.SniffLiterals))
        {
            return true;
        }

        if (SniffLiterals == null ||
            item.SniffLiterals == null ||
            SniffLiterals.Count != item.SniffLiterals.Count)
        {
            return false;
        }

        foreach (string sniffLiteral in SniffLiterals)
        {
            if (!item.SniffLiterals.Contains(sniffLiteral))
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

            result = (result * 31) + m_regexOptions.GetHashCode();
            result = (result * 31) + RotationPeriod.GetHashCode();
            result = (result * 31) + DetectionMetadata.GetHashCode();
#endif

            // Use xor for set values to be order-independent.
            if (SniffLiterals != null)
            {
                int xor_0 = 0;
                foreach (var sniffLiteral in SniffLiterals)
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

    public const string DefaultRedactionToken = "***";

    public virtual IEnumerable<Detection> GetDetections(string input,
                                                        bool generateCrossCompanyCorrelatingIds,
                                                        string defaultRedactionToken = DefaultRedactionToken,
                                                        IRegexEngine? regexEngine = null)
    {
        if (input == null)
        {
            yield break;
        }

        bool runRegexes = SniffLiterals == null;

        if (SniffLiterals != null)
        {
            foreach (string sniffLiteral in SniffLiterals)
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
            foreach (UniversalMatch match in regexEngine.Matches(input, Pattern, m_regexOptions, captureGroup: "refine"))
            {
                startIndex = match.Index + 1;

                string? redactionToken =
                    generateCrossCompanyCorrelatingIds && DetectionMetadata.HasFlag(DetectionMetadata.HighEntropy)
                        ? $"{Id}:{GenerateCrossCompanyCorrelatingId(match.Value)}"
                        : defaultRedactionToken;

                var moniker = GetMatchIdAndName(match.Value);
                if (moniker == default)
                {
                    continue;
                }

                string id = moniker.Item1;
                string name = moniker.Item2;

                yield return new Detection(id,
                                           name,
                                           match.Index,
                                           match.Length,
                                           DetectionMetadata,
                                           RotationPeriod,
                                           redactionToken);
            }

        }
    }

    public virtual IEnumerable<string> GenerateTestExamples()
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

    public virtual string GetMatchMoniker(string match) => $"{GetMatchIdAndName(match)!.Item1}.{GetMatchIdAndName(match)!.Item2}";

    public virtual Tuple<string, string>? GetMatchIdAndName(string match) => new Tuple<string, string>(Id, Name);

    public virtual string Pattern { get; protected set; }

#if NET7_0_OR_GREATER
    protected const RegexOptions DefaultRegexOptions = RegexOptions.Compiled | RegexOptions.ExplicitCapture | RegexOptions.NonBacktracking;
#else
    protected const RegexOptions DefaultRegexOptions = RegexOptions.Compiled | RegexOptions.ExplicitCapture;
#endif

    /// <summary>
    /// Gets or sets an opaque, stable identifier for the pattern (corresponding to a SARIF 'reportingDescriptorReference.id' value).
    /// </summary>
    public string Id { get; protected set; }

    /// <summary>
    /// Gets or sets a readable name for the detection.
    /// </summary>
    public string Name { get; protected set; }

    public TimeSpan RotationPeriod { get; set; }

    /// <summary>
    /// Gets or sets one or more regular expression options.
    /// </summary>
    /// <remarks>Options may not be available when .NET is not used to
    /// provide regex processing.</remarks>
    private readonly RegexOptions m_regexOptions;

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
    public virtual ISet<string>? SniffLiterals { get; protected set; }

    private readonly Func<string[]>? m_sampleGenerator;

    /// <summary>
    /// Gets or sets a property that describes pattern characteristics such as whether this detection finds high
    /// entropy secrets (that can be hashed for telemetry) or if the secret kind has been obsoleted by a newer format.
    /// </summary>
    /// <remarks>Options may not be available when .NET is not used to
    /// provide regex processing.</remarks>
    public DetectionMetadata DetectionMetadata { get; protected set; }

    internal static string NormalizeGroupsPattern(string pattern)
    {
        if (pattern.IndexOf("?P<") != -1)
        {
            return pattern.Replace("?P<", "?<");
        }

        return pattern;
    }

    public bool ShouldSerializeRotationPeriod() => false;
}
