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

public class SecretMasker : ISecretMasker, IDisposable
{
    IRegexEngine? _regexEngine;

    public static Version Version => RetrieveVersion();

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
        m_disposed = false;

        RegexPatterns = regexSecrets != null
            ? new HashSet<RegexPattern>(regexSecrets)
            : new HashSet<RegexPattern>();

        m_generateCorrelatingIds = generateCorrelatingIds;

        ExplicitlyAddedSecretLiterals = new HashSet<SecretLiteral>();
        EncodedSecretLiterals = new HashSet<SecretLiteral>();
        LiteralEncoders = new HashSet<LiteralEncoder>();

        _regexEngine = regexEngine ??= CachedDotNetRegex.Instance;

        DefaultRegexRedactionToken = defaultRegexRedactionToken ?? RegexPattern.FallbackRedactionToken;
        DefaultLiteralRedactionToken = defaultLiteralRedactionToken ?? SecretLiteral.FallbackRedactionToken;
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
        // Write section.
        try
        {
            SyncObject.EnterWriteLock();
            _ = RegexPatterns.Add(regexSecret);
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
    /// Masks secrets detected by <see cref="DetectSecrets(string)"/> in the
    /// input, replacing them with <see cref="Detection.RedactionToken"/>.
    /// </summary>
    /// <remarks>
    /// When secrets overlap or are adjacent to each other, the entire range
    /// encompassing them is masked and the leftmost detection's redaction token
    /// is used. If there is more than one overlapping leftmost detection, then
    /// the redaction token among them that sorts first by ordinal
    /// case-sesstring comparison is used.
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

        if (RegexPatterns.Count == 0 &&
            EncodedSecretLiterals.Count == 0 &&
            ExplicitlyAddedSecretLiterals.Count == 0)
        {
            yield break;
        }

        // Read section.
        try
        {
            SyncObject.EnterReadLock();
            var stopwatch = Stopwatch.StartNew();

            // Get indexes and lengths of all substrings that will be replaced.
            foreach (RegexPattern regexSecret in RegexPatterns)
            {
                foreach (var detection in regexSecret.GetDetections(input, m_generateCorrelatingIds, DefaultRegexRedactionToken, _regexEngine))
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
        if (disposing && !m_disposed)
        {
            SyncObject.Dispose();
            m_disposed = true;
        }
    }

    public void AddPatterns(IEnumerable<RegexPattern> regexPatterns)
    {
        foreach (var regexPattern in regexPatterns)
        {
            AddRegex(regexPattern);
        }
    }


    private readonly bool m_generateCorrelatingIds;
    public HashSet<LiteralEncoder> LiteralEncoders { get; }
    public HashSet<SecretLiteral> EncodedSecretLiterals { get; }
    public HashSet<SecretLiteral> ExplicitlyAddedSecretLiterals { get; }

    public ReaderWriterLockSlim SyncObject = new(LockRecursionPolicy.NoRecursion);

    private bool m_disposed;
}
