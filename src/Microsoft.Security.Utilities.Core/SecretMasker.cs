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
    /// When secrets overlap or are adjacent to each other, the entire range
    /// encompassing them is masked and the leftmost detection's redaction token
    /// is used. If there is more than one overlapping leftmost detection, then
    /// the redaction token among them that sorts first by ordinal
    /// case-sensitive string comparison is used.
    ///
    /// The detection action receives  all detections, including those that
    /// overlap or are adjacent to others. The detections are received in order
    /// sorted from left to right, then by redaction token in ordinal
    /// case-sensitive order. In the extreme case that there are multiple
    /// detections with the same start index and the same redaction token, the
    /// relative order in which these are received is arbitrary and may change
    /// between runs.
    /// </remarks>
    /// <param name="input">The input to mask.</param>
    /// <param name="detectionAction">An optional action to perform on each detection.</param>
    public string MaskSecrets(string input, Action<Detection>? detectionAction = null)
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

    private string MaskSecretsCore(string input, Action<Detection>? detectionAction)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        List<Detection> detections = DetectSecretsCore(input);

        if (detections.Count == 0)
        {
            return input;
        }

        detections.Sort((x, y) =>
        {
            int result = x.Start.CompareTo(y.Start);
            if (result == 0)
            {
                result = string.CompareOrdinal(x.RedactionToken, y.RedactionToken);
            }
            return result;
        });

        s_stringBuilder ??= new StringBuilder();
        s_stringBuilder.Length = 0;

        int startIndex = 0;
        for (int i = 0; i < detections.Count; i++)
        {
            Detection detection = detections[i];
            detectionAction?.Invoke(detection);

            // Absorb overlapping and adjacent detections into leftmost detection.
            int endIndex = detection.End;
            while (i < detections.Count - 1 && detections[i + 1].Start <= endIndex)
            {
                Detection absorbedDetection = detections[i + 1];
                detectionAction?.Invoke(absorbedDetection);
                endIndex = Math.Max(endIndex, absorbedDetection.End);
                i++;
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

    private List<Detection> DetectSecretsCore(string input)
    {
        // NOTE: MinimumSecretLength changes are not protected by the lock. Make
        // sure to read it only once in this method so that a single masking or
        // detection operation does not use more than one value.
        int minimumSecretLength = MinimumSecretLength;

        if (input == null || input.Length < minimumSecretLength)
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
