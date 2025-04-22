// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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

public class SecretMasker : ISecretMasker
{
    private readonly IRegexEngine _regexEngine;
    private HighPerformanceScanner? _highPerformanceScanner;
    private Dictionary<string, IList<RegexPattern>>? _highPerformanceSignatureToPatternsMap;

    public static Version Version { get; } = RetrieveVersion();

    internal static Version RetrieveVersion()
    {
        var version = new Version(ThisAssembly.AssemblyFileVersion);
        return new Version(version.Major, version.Minor, version.Build);
    }

    public SecretMasker() : this(default, default, default, default, default)
    {
    }

    public SecretMasker(IEnumerable<RegexPattern>? regexSecrets,
                        bool generateCorrelatingIds = false,
                        IRegexEngine? regexEngine = default,
                        string? defaultRegexRedactionToken = null,
                        string? defaultLiteralRedactionToken = null)
    {
        _disposed = false;

        RegexPatterns = regexSecrets != null
            ? new HashSet<RegexPattern>(regexSecrets)
            : new HashSet<RegexPattern>();

        _generateCorrelatingIds = generateCorrelatingIds;

        ExplicitlyAddedSecretLiterals = new HashSet<SecretLiteral>();
        EncodedSecretLiterals = new HashSet<SecretLiteral>();
        LiteralEncoders = new HashSet<LiteralEncoder>();

        _regexEngine = regexEngine ??= CachedDotNetRegex.Instance;

        DefaultRegexRedactionToken = defaultRegexRedactionToken ?? RegexPattern.FallbackRedactionToken;
        DefaultLiteralRedactionToken = defaultLiteralRedactionToken ?? SecretLiteral.FallbackRedactionToken;

        AddHighPerformancePatterns(RegexPatterns);
    }

    // We don't permit secrets great than 5 characters in length to be
    // skipped at masking time. The secrets that will be ignored when
    // masking will N - 1 of this property value.
    public static int MinimumSecretLengthCeiling { get; set; }

    protected SecretMasker(SecretMasker copy)
    {
        // Read section.
        try
        {
            copy.SyncObject.EnterReadLock();

            _regexEngine = copy._regexEngine;
            _highPerformanceScanner = copy._highPerformanceScanner;
            _highPerformanceSignatureToPatternsMap = copy._highPerformanceSignatureToPatternsMap;
            _generateCorrelatingIds = copy._generateCorrelatingIds;

            MinimumSecretLength = copy.MinimumSecretLength;
            DefaultRegexRedactionToken = copy.DefaultRegexRedactionToken;
            DefaultLiteralRedactionToken = copy.DefaultLiteralRedactionToken;
            RegexPatterns = new HashSet<RegexPattern>(copy.RegexPatterns);
            LiteralEncoders = new HashSet<LiteralEncoder>(copy.LiteralEncoders);
            EncodedSecretLiterals = new HashSet<SecretLiteral>(copy.EncodedSecretLiterals);
            ExplicitlyAddedSecretLiterals = new HashSet<SecretLiteral>(copy.ExplicitlyAddedSecretLiterals);
        }
        finally
        {
            if (copy.SyncObject.IsReadLockHeld)
            {
                copy.SyncObject.ExitReadLock();
            }
        }
    }

    [ThreadStatic]
    private static StringBuilder? s_stringBuilder;

    public virtual string DefaultRegexRedactionToken { get; set; }

    public virtual string DefaultLiteralRedactionToken { get; set; }

    public virtual HashSet<RegexPattern> RegexPatterns { get; protected set; }

    /// <summary>
    /// Gets the total time in ticks spent masking content for the lifetime of this masker instance.
    /// </summary>
    public long ElapsedMaskingTime { get; private set; }

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public virtual void AddRegex(RegexPattern regexSecret)
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
        if (input == null)
        {
            return string.Empty;
        }

        var enumerableDetections = DetectSecrets(input);

        // Short-circuit if nothing to replace.
        if (!enumerableDetections.Any())
        {
            return input;
        }

        List<Detection> detections = enumerableDetections.ToList();
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
    /// Gets or sets the minimum allowable size of a string that's a candidate for masking.
    /// </summary>
    public virtual int MinimumSecretLength { get; set; }

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public void AddValue(string value)
    {
        // Test for empty.
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        if (value.Length < MinimumSecretLength)
        {
            return;
        }

        var secretLiterals = new List<SecretLiteral>(new[] { new SecretLiteral(value) });

        // Read section.
        LiteralEncoder[] literalEncoders;
        try
        {
            SyncObject.EnterReadLock();

            // Test whether already added.
            if (ExplicitlyAddedSecretLiterals.Contains(secretLiterals[0]))
            {
                return;
            }

            // Read the value encoders.
            literalEncoders = LiteralEncoders.ToArray();
        }
        finally
        {
            if (SyncObject.IsReadLockHeld)
            {
                SyncObject.ExitReadLock();
            }
        }

        // Compute the encoded values.
        foreach (LiteralEncoder literalEncoder in literalEncoders)
        {
            string encodedValue = literalEncoder(value);
            if (!string.IsNullOrEmpty(encodedValue) && encodedValue.Length >= MinimumSecretLength)
            {
                secretLiterals.Add(new SecretLiteral(encodedValue));
            }
        }

        // Write section.
        try
        {
            SyncObject.EnterWriteLock();

            // Add the values.
            _ = ExplicitlyAddedSecretLiterals.Add(secretLiterals[0]);
            foreach (SecretLiteral secretLiteral in secretLiterals)
            {
                _ = EncodedSecretLiterals.Add(secretLiteral);
            }
        }
        finally
        {
            if (SyncObject.IsWriteLockHeld)
            {
                SyncObject.ExitWriteLock();
            }
        }
    }

    /// <summary>
    /// This implementation assumes no more than one thread is adding regexes, values, or encoders at any given time.
    /// </summary>
    public void AddLiteralEncoder(LiteralEncoder encoder)
    {
        SecretLiteral[] originalSecrets;

        // Read section.
        try
        {
            SyncObject.EnterReadLock();

            if (LiteralEncoders.Contains(encoder))
            {
                return;
            }

            // Read the original value secrets.
            originalSecrets = ExplicitlyAddedSecretLiterals.ToArray();
        }
        finally
        {
            if (SyncObject.IsReadLockHeld)
            {
                SyncObject.ExitReadLock();
            }
        }

        // Compute the encoded values.
        var encodedSecrets = new List<SecretLiteral>();
        foreach (SecretLiteral originalSecret in originalSecrets)
        {
            string encodedValue = encoder(originalSecret.Value);
            if (!string.IsNullOrEmpty(encodedValue) && encodedValue.Length >= MinimumSecretLength)
            {
                encodedSecrets.Add(new SecretLiteral(encodedValue));
            }
        }

        // Write section.
        try
        {
            SyncObject.EnterWriteLock();

            // Add the encoder.
            _ = LiteralEncoders.Add(encoder);

            // Add the values.
            foreach (SecretLiteral encodedSecret in encodedSecrets)
            {
                _ = EncodedSecretLiterals.Add(encodedSecret);
            }
        }
        finally
        {
            if (SyncObject.IsWriteLockHeld)
            {
                SyncObject.ExitWriteLock();
            }
        }
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            yield break;
        }

        // Read section.
        try
        {
            SyncObject.EnterReadLock();
            var stopwatch = Stopwatch.StartNew();

            if (_highPerformanceScanner != null)
            {
                foreach (HighPerformanceDetection highPerformanceDetection in _highPerformanceScanner.Scan(input))
                {
                    string found = input.Substring(highPerformanceDetection.Start, highPerformanceDetection.Length);
                    foreach (RegexPattern pattern in _highPerformanceSignatureToPatternsMap![highPerformanceDetection.Signature])
                    {
                        Detection? detection = FinalizeHighPerformanceDetection(highPerformanceDetection, found, pattern);
                        if (detection != null)
                        {
                            yield return detection;
                            break;
                        }
                    }
                }
            }

            // Get indexes and lengths of all substrings that will be replaced.
            foreach (RegexPattern regexSecret in RegexPatterns)
            {
                if (_highPerformanceScanner != null && regexSecret is IHighPerformanceScannableKey)
                {
                    continue;
                }

                foreach (var detection in regexSecret.GetDetections(input, _generateCorrelatingIds, DefaultRegexRedactionToken, _regexEngine))
                {
                    yield return detection;
                }
            }

            foreach (SecretLiteral secretLiteral in EncodedSecretLiterals)
            {
                foreach (var detection in secretLiteral.GetDetections(input, DefaultLiteralRedactionToken))
                {
                    yield return detection;
                }
            }

            ElapsedMaskingTime += stopwatch.ElapsedTicks;
        }
        finally
        {
            if (SyncObject.IsReadLockHeld)
            {
                SyncObject.ExitReadLock();
            }
        }
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
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public virtual SecretMasker Clone()
    {
        return new SecretMasker(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            SyncObject.Dispose();
            _disposed = true;
        }
    }

    public void AddPatterns(IEnumerable<RegexPattern> regexPatterns)
    {
        // Write section.
        try
        {
            SyncObject.EnterWriteLock();

            foreach (var pattern in regexPatterns)
            {
                RegexPatterns.Add(pattern);
            }

            AddHighPerformancePatterns(regexPatterns);
        }
        finally
        {
            if (SyncObject.IsWriteLockHeld)
            {
                SyncObject.ExitWriteLock();
            }
        }
    }

    private void AddHighPerformancePatterns(IEnumerable<RegexPattern> patterns)
    {
        List<CompiledHighPerformancePattern>? compiledHighPerformancePatterns = null;

        foreach (var pattern in patterns)
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
                var highPerformancePattern = CompiledHighPerformancePattern.ForSignature(signature)!;
                Debug.Assert(highPerformancePattern != null, "Every signature of high-performance compatible patterns have a compiled counterpart.");
                compiledHighPerformancePatterns.Add(highPerformancePattern!);

                if (!_highPerformanceSignatureToPatternsMap.TryGetValue(signature, out IList<RegexPattern>? patternsForSignature))
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

    private readonly bool _generateCorrelatingIds;
    public HashSet<LiteralEncoder> LiteralEncoders { get; }
    public HashSet<SecretLiteral> EncodedSecretLiterals { get; }
    public HashSet<SecretLiteral> ExplicitlyAddedSecretLiterals { get; }

    public ReaderWriterLockSlim SyncObject { get; } = new(LockRecursionPolicy.NoRecursion);

    private bool _disposed;
}
