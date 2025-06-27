// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

#nullable enable

namespace Microsoft.Security.Utilities;

/// <summary>
/// A callback method that accepts and encodes or escapes a literal.
/// </summary>
/// <param name="literal">The string literal to escape or encode.</param>
/// <returns>The escaped or encoded literal.</returns>
public delegate string LiteralEncoder(string literal);

public sealed class SecretMasker : ISecretMasker
{
    private readonly bool _generateCorrelatingIds;
    private readonly IRegexEngine _regexEngine;
    private readonly HashSet<LiteralEncoder> _literalEncoders;
    private readonly HashSet<SecretLiteral> _encodedSecretLiterals;
    private readonly HashSet<SecretLiteral> _explicitlyAddedSecretLiterals;
    private readonly HashSet<RegexPattern> _regexPatterns;

    private long _elapsedMaskingTicks;
    private HighPerformanceScanner? _highPerformanceScanner;
    private Dictionary<string, List<RegexPattern>>? _highPerformanceSignatureToPatternsMap;

    [ThreadStatic]
    private static StringBuilder? s_stringBuilder;

    public static Version Version { get; } = RetrieveVersion();

    internal static Version RetrieveVersion()
    {
        var version = new Version(ThisAssembly.AssemblyFileVersion);
        return new Version(version.Major, version.Minor, version.Build);
    }

    public SecretMasker() : this(default, default, default, default, default)
    {
    }

    public SecretMasker(IEnumerable<RegexPattern>? regexSecrets = null,
                        bool generateCorrelatingIds = false,
                        IRegexEngine? regexEngine = default,
                        string? defaultRegexRedactionToken = null,
                        string? defaultLiteralRedactionToken = null)
    {
        _regexPatterns = new HashSet<RegexPattern>(regexSecrets ?? []);
        _generateCorrelatingIds = generateCorrelatingIds;

        _explicitlyAddedSecretLiterals = new HashSet<SecretLiteral>();
        _encodedSecretLiterals = new HashSet<SecretLiteral>();
        _literalEncoders = new HashSet<LiteralEncoder>();

        _regexEngine = regexEngine ?? CachedDotNetRegex.Instance;

        DefaultRegexRedactionToken = defaultRegexRedactionToken ?? RegexPattern.FallbackRedactionToken;
        DefaultLiteralRedactionToken = defaultLiteralRedactionToken ?? SecretLiteral.FallbackRedactionToken;

        AddHighPerformancePatterns(_regexPatterns);
    }

    public string DefaultRegexRedactionToken { get; }

    public string DefaultLiteralRedactionToken { get; }

    /// <summary>
    /// Gets the total time spent masking content for the lifetime of this masker instance.
    /// </summary>
    public TimeSpan ElapsedMaskingTime => TimeSpan.FromTicks(_elapsedMaskingTicks);

    public void AddRegex(RegexPattern regexSecret)
    {
        AddPatterns([regexSecret]);
    }

    /// <summary>
    /// Masks secrets detected by <see cref="DetectSecrets(string)"/> in the
    /// input, replacing them with <see cref="Detection.RedactionToken"/>.
    /// </summary>
    /// <remarks>
    /// Detections are sorted by their start index ascending (leftmost first),
    /// then by length descending (longest first), then by ID, and finally by
    /// redaction token. The callback receives detections in this order.
    ///
    /// When secrets overlap or are adjacent to each other, the entire range
    /// encompassing them is masked and the redaction token of the detection
    /// among them that sorts first is used.
    ///
    /// Detections that have identical range (start index and length) are treated
    /// as duplicates and only the one that sorts first is sent to the callback.
    ///
    /// All other detections, including those that partially overlap or are adjacent
    /// to each other will be sent to the callback.
    /// </remarks>
    /// <param name="input">The input to mask.</param>
    /// <param name="detectionAction">An optional action to perform on each detection.</param>
    public string MaskSecrets(string input, Action<Detection>? detectionAction = null)
    {
        return MaskSecrets(new StringInput(input), detectionAction);
    }

#if NET
    public string MaskSecrets(ReadOnlyMemory<char> input, Action<Detection>? detectionAction = null)
    {
        return MaskSecrets(new StringInput(input), detectionAction);
    }
#endif

    private string MaskSecrets(StringInput input, Action<Detection>? detectionAction = null)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            return MaskSecretsCore(input, detectionAction);
        }
        finally
        {
            Interlocked.Add(ref _elapsedMaskingTicks, stopwatch.ElapsedTicks);
        }
    }

    private string MaskSecretsCore(StringInput input, Action<Detection>? detectionAction)
    {
        if (input.Length == 0)
        {
            return string.Empty;
        }

        List<Detection> detections = DetectSecretsCore(input);

        if (detections.Count == 0)
        {
            return input.ToString();
        }

        SortDetectionsForMasking(detections);

        s_stringBuilder ??= new StringBuilder();
        s_stringBuilder.Length = 0;

        int startIndex = 0;
        int index;
        for (index = 0; index < detections.Count; index++)
        {
            Detection detection = detections[index];
            detectionAction?.Invoke(detection);
            SkipDuplicates(detection);

            // Absorb overlapping and adjacent detections into one redaction.
            int endIndex = detection.End;
            while (index < detections.Count - 1 && detections[index + 1].Start <= endIndex)
            {
                Detection absorbedDetection = detections[++index];
                detectionAction?.Invoke(absorbedDetection);
                SkipDuplicates(absorbedDetection);
                endIndex = Math.Max(endIndex, absorbedDetection.End);
            }

            s_stringBuilder.Append(input, startIndex, detection.Start - startIndex);
            s_stringBuilder.Append(detection.RedactionToken);
            startIndex = endIndex;
        }

        if (startIndex < input.Length)
        {
            s_stringBuilder.Append(input, startIndex, input.Length - startIndex);
        }

        return s_stringBuilder.ToString();

        // Given sorted order established above, skip any detection that has the
        // same start index and length as previous one.
        void SkipDuplicates(Detection detection)
        {
            while (index < detections.Count - 1 &&
                detections[index + 1].Start == detection.Start &&
                detections[index + 1].Length == detection.Length)
            {
                index++;
            }
        }
    }

    internal static void SortDetectionsForMasking(List<Detection> detections)
    {
        detections.Sort(static (x, y) =>
        {
            // Sort by start position. (Leftmost first.)
            int result = x.Start.CompareTo(y.Start);
            if (result != 0) return result;

            // Then by length descending. (Longest first.)
            result = y.Length.CompareTo(x.Length);
            if (result != 0) return result;

            // Then by kind descending. (Literal matches before regex matches,
            // which is descending by underlying enum value.) Note that we do
            // not rely on the the differences in redaction token nor ID to
            // ensure this because regexes can have null ID and redaction
            // literal vs regex redaction token can be configured.
            result = y.Kind.CompareTo(x.Kind);
            if (result != 0) return result;

            // Then by ID. This ensures that the C3ID generation option doesn't
            // impact ordering.
            result = string.CompareOrdinal(x.Id, y.Id);
            if (result != 0) return result;

            // And finally by redaction token. This ensures that the redaction
            // result is well-defined even in the unlikely case that there are
            // detections that are tied on all of the above.
            result = string.CompareOrdinal(x.RedactionToken, y.RedactionToken);
            return result;
        });
    }

    /// <summary>
    /// Gets or sets the minimum length of a secret that can be detected or masked.
    /// </summary>
    public int MinimumSecretLength { get; set; }

    public void AddValue(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        var literal = new SecretLiteral(value);
        SyncObject.EnterWriteLock();
        try
        {
            if (!_explicitlyAddedSecretLiterals.Add(literal))
            {
                return;
            }

            _encodedSecretLiterals.Add(literal);
            foreach (LiteralEncoder literalEncoder in _literalEncoders)
            {
                string encodedValue = literalEncoder(value);
                if (!string.IsNullOrEmpty(encodedValue))
                {
                    _encodedSecretLiterals.Add(new SecretLiteral(encodedValue));
                }
            }
        }
        finally
        {
            SyncObject.ExitWriteLock();
        }
    }

    public void AddLiteralEncoder(LiteralEncoder encoder)
    {
        SyncObject.EnterWriteLock();
        try
        {
            if (!_literalEncoders.Add(encoder))
            {
                return;
            }

            foreach (SecretLiteral originalSecret in _explicitlyAddedSecretLiterals)
            {
                string encodedValue = encoder(originalSecret.Value);
                if (!string.IsNullOrEmpty(encodedValue))
                {
                    _encodedSecretLiterals.Add(new SecretLiteral(encodedValue));
                }
            }
        }
        finally
        {
            SyncObject.ExitWriteLock();
        }
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        return DetectSecrets(new StringInput(input));
    }

#if NET
    public IEnumerable<Detection> DetectSecrets(ReadOnlyMemory<char> input)
    {
        return DetectSecrets(new StringInput(input));
    }
#endif

    private IEnumerable<Detection> DetectSecrets(StringInput input)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            return DetectSecretsCore(input);
        }
        finally
        {
            Interlocked.Add(ref _elapsedMaskingTicks, stopwatch.ElapsedTicks);
        }
    }

    // NOTE: It is important that this method, through which all calls to public
    // DetectSecrets and MaskSecrets API are routed, is not implemented using an
    // iterator (yield return). We must guarantee the following:
    //
    //  1. Any lock taken during a call to the library will released before the
    //     method returns.
    //
    //  2. Any ReadOnlyMemory<char> passed to the library will not be used after
    //     the method returns.
    private List<Detection> DetectSecretsCore(StringInput input)
    {
        // NOTE: MinimumSecretLength changes are not protected by the lock. Make
        // sure to read it only once in this method so that a single masking or
        // detection operation does not use more than one value.
        int minimumSecretLength = MinimumSecretLength;

        if (input.Length == 0 || input.Length < minimumSecretLength)
        {
            return [];
        }

        var detections = new List<Detection>();
        SyncObject.EnterReadLock();
        try
        {
            List<HighPerformanceDetection>? highPerformanceDetections = _highPerformanceScanner?.Scan(input);

            if (highPerformanceDetections != null)
            {
                foreach (HighPerformanceDetection highPerformanceDetection in highPerformanceDetections)
                {
                    if (highPerformanceDetection.Length < minimumSecretLength)
                    {
                        continue;
                    }
                    string found = input.Substring(highPerformanceDetection.Start, highPerformanceDetection.Length);
                    foreach (RegexPattern pattern in _highPerformanceSignatureToPatternsMap![highPerformanceDetection.Signature])
                    {
                        Detection? detection = FinalizeHighPerformanceDetection(highPerformanceDetection, found, pattern);
                        if (detection != null)
                        {
                            detections.Add(detection);
                        }
                    }
                }
            }

            foreach (RegexPattern regexSecret in _regexPatterns)
            {
                if (_highPerformanceScanner != null && regexSecret is IHighPerformanceScannableKey)
                {
                    continue;
                }

                foreach (Detection detection in regexSecret.GetDetections(input, _generateCorrelatingIds, DefaultRegexRedactionToken, _regexEngine))
                {
                    if (detection.Length >= minimumSecretLength)
                    {
                        detections.Add(detection);
                    }
                }
            }

            foreach (SecretLiteral secretLiteral in _encodedSecretLiterals)
            {
                if (secretLiteral.Value.Length < minimumSecretLength)
                {
                    continue;
                }

                foreach (Detection detection in secretLiteral.GetDetections(input, DefaultLiteralRedactionToken))
                {
                    detections.Add(detection);
                }
            }
        }
        finally
        {
            SyncObject.ExitReadLock();
        }

        return detections;
    }

    private Detection? FinalizeHighPerformanceDetection(HighPerformanceDetection detection, string found, RegexPattern pattern)
    {
        Tuple<string, string>? result = pattern.GetMatchIdAndName(found);
        if (result == null)
        {
            return null;
        }

        string? c3id = null;
        string preciseId = result.Item1;

        Debug.Assert(pattern.DetectionMetadata.HasFlag(DetectionMetadata.HighEntropy), "High-performance patterns should have high-entropy and therefore can use C3ID.");
        if (_generateCorrelatingIds)
        {
            c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(found);
        }

        string redactionToken = c3id != null
            ? $"{preciseId}:{c3id}"
            : RegexPattern.FallbackRedactionToken;

        return new Detection(id: preciseId,
                             name: result.Item2,
                             label: pattern.Label,
                             start: detection.Start,
                             length: detection.Length,
                             redactionToken: redactionToken,
                             crossCompanyCorrelatingId: c3id,
                             metadata: pattern.DetectionMetadata,
                             rotationPeriod: pattern.RotationPeriod);
    }

    public void Dispose()
    {
        SyncObject.Dispose();
    }

    public void AddPatterns(IEnumerable<RegexPattern> regexPatterns)
    {
        SyncObject.EnterWriteLock();
        try
        {
            foreach (RegexPattern pattern in regexPatterns)
            {
                _regexPatterns.Add(pattern);
            }

            AddHighPerformancePatterns(regexPatterns);
        }
        finally
        {
            SyncObject.ExitWriteLock();
        }
    }

    private void AddHighPerformancePatterns(IEnumerable<RegexPattern> patterns)
    {
        List<CompiledHighPerformancePattern>? compiledHighPerformancePatterns = null;

        foreach (RegexPattern pattern in patterns)
        {
            if (pattern is not IHighPerformanceScannableKey)
            {
                continue;
            }

            compiledHighPerformancePatterns ??= new();
            _highPerformanceSignatureToPatternsMap ??= new();

            Debug.Assert(pattern.Signatures != null, "High-performance scannable key must have non-null signatures.");
            foreach (string signature in pattern.Signatures!)
            {
                CompiledHighPerformancePattern highPerformancePattern = CompiledHighPerformancePattern.ForSignature(signature)!;
                Debug.Assert(highPerformancePattern != null, "Every signature of high-performance compatible patterns have a compiled counterpart.");
                compiledHighPerformancePatterns.Add(highPerformancePattern!);

                if (!_highPerformanceSignatureToPatternsMap.TryGetValue(signature, out List<RegexPattern>? patternsForSignature))
                {
                    patternsForSignature = new List<RegexPattern>();
                    _highPerformanceSignatureToPatternsMap[signature] = patternsForSignature;
                }

                patternsForSignature.Add(pattern);
            }
        }

        if (compiledHighPerformancePatterns != null)
        {
            _highPerformanceScanner ??= new();
            _highPerformanceScanner.AddPatterns(compiledHighPerformancePatterns);
        }
    }

    // This is a test hook to test without using the high performance scanner.
    // There is no reason for a public API consumer to opt into the slower
    // scanning, but we want to exercise the general regexes we distribute in
    // JSON in our tests. Note that adding additional patterns after calling
    // this will re-enable high-performance scanning for any new patterns until
    // this is called again.
    internal void DisableHighPerformanceScannerForTests()
    {
        _highPerformanceScanner = null;
        _highPerformanceSignatureToPatternsMap = null;
    }

    public ReaderWriterLockSlim SyncObject { get; } = new(LockRecursionPolicy.SupportsRecursion);
}
