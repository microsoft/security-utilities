// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A callback method that accepts and encodes or escapes a literal.
/// </summary>
/// <param name="literal">The string literal to escape or encode.</param>
/// <returns>The escaped or encoded literal.</returns>
public delegate string LiteralEncoder(string literal);

[ExcludeFromCodeCoverage]
internal class SecretMasker : ISecretMasker, IDisposable
{
    public SecretMasker(IEnumerable<RegexPattern>? regexSecrets, bool generateSha256Hashes = false)
    {
        m_disposed = false;

        RegexPatterns = regexSecrets != null
            ? new HashSet<RegexPattern>(regexSecrets)
            : new HashSet<RegexPattern>();

        m_generateSha256Hashes = generateSha256Hashes;

        m_explicitlyAddedSecretLiterals = new HashSet<SecretLiteral>();
        m_encodedSecretLiterals = new HashSet<SecretLiteral>();
        m_literalEncoders = new HashSet<LiteralEncoder>();
    }

    public SecretMasker()
        : this(new HashSet<RegexPattern>())
    {
    }

    // We don't permit secrets great than 5 characters in length to be
    // skipped at masking time. The secrets that will be ignored when
    // masking will N - 1 of this property value.
    public static int MinimumSecretLengthCeiling { get; set; }

    private SecretMasker(SecretMasker copy)
    {
        // Read section.
        try
        {
            copy.m_lock.EnterReadLock();
            MinimumSecretLength = copy.MinimumSecretLength;
            RegexPatterns = new HashSet<RegexPattern>(copy.RegexPatterns);
            m_literalEncoders = new HashSet<LiteralEncoder>(copy.m_literalEncoders);
            m_encodedSecretLiterals = new HashSet<SecretLiteral>(copy.m_encodedSecretLiterals);
            m_explicitlyAddedSecretLiterals = new HashSet<SecretLiteral>(copy.m_explicitlyAddedSecretLiterals);
        }
        finally
        {
            if (copy.m_lock.IsReadLockHeld)
            {
                copy.m_lock.ExitReadLock();
            }
        }
    }

    [ThreadStatic]
    private static StringBuilder? s_stringBuilder;

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
            m_lock.EnterWriteLock();
            _ = RegexPatterns.Add(regexSecret);
        }
        finally
        {
            if (m_lock.IsWriteLockHeld)
            {
                m_lock.ExitWriteLock();
            }
        }
    }

    public string MaskSecrets(string input)
    {
        if (input == null)
        {
            return string.Empty;
        }

        var detections = DetectSecrets(input);

        // Short-circuit if nothing to replace.
        if (detections.Count == 0)
        {
            return input;
        }

        // Merge positions into ranges of characters to replace.
        var currentDetections = new List<Detection>();
        Detection? currentDetection = default;
        foreach (Detection detection in detections.OrderBy(x => x.Start))
        {
            if (object.Equals(currentDetection, null))
            {
                currentDetection =
                    new Detection(detection.Id,
                                  detection.Name,
                                  detection.Start,
                                  detection.Length,
                                  detection.Metadata,
                                  detection.RotationPeriod,
                                  detection.Sha256Hash,
                                  detection.RedactionToken);

                currentDetections.Add(currentDetection);
            }
            else
            {
                if (detection.Start <= currentDetection.End)
                {
                    // Overlapping case or contiguous case.
                    currentDetection.Length = Math.Max(currentDetection.End, detection.End) - currentDetection.Start;
                }
                else
                {
                    // No overlap
                    // Overlapping case.
                    currentDetection =
                        new Detection(detection.Id,
                                      detection.Name,
                                      detection.Start,
                                      detection.Length,
                                      detection.Metadata,
                                      detection.RotationPeriod,
                                      detection.Sha256Hash,
                                      detection.RedactionToken);

                    currentDetections.Add(currentDetection);
                }
            }
        }

        s_stringBuilder ??= new StringBuilder();
        s_stringBuilder.Length = 0;

        int startIndex = 0;
        foreach (var detection in currentDetections)
        {
            _ = s_stringBuilder.Append(input.Substring(startIndex, detection.Start - startIndex))
                    .Append(detection.RedactionToken);

            startIndex = detection.Start + detection.Length;
        }

        if (startIndex < input.Length)
        {
            _ = s_stringBuilder.Append(input.Substring(startIndex));
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
            m_lock.EnterReadLock();

            // Test whether already added.
            if (m_explicitlyAddedSecretLiterals.Contains(secretLiterals[0]))
            {
                return;
            }

            // Read the value encoders.
            literalEncoders = m_literalEncoders.ToArray();
        }
        finally
        {
            if (m_lock.IsReadLockHeld)
            {
                m_lock.ExitReadLock();
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
            m_lock.EnterWriteLock();

            // Add the values.
            _ = m_explicitlyAddedSecretLiterals.Add(secretLiterals[0]);
            foreach (SecretLiteral secretLiteral in secretLiterals)
            {
                _ = m_encodedSecretLiterals.Add(secretLiteral);
            }
        }
        finally
        {
            if (m_lock.IsWriteLockHeld)
            {
                m_lock.ExitWriteLock();
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
            m_lock.EnterReadLock();

            if (m_literalEncoders.Contains(encoder))
            {
                return;
            }

            // Read the original value secrets.
            originalSecrets = m_explicitlyAddedSecretLiterals.ToArray();
        }
        finally
        {
            if (m_lock.IsReadLockHeld)
            {
                m_lock.ExitReadLock();
            }
        }

        // Compute the encoded values.
        var encodedSecrets = new List<SecretLiteral>();
        foreach (SecretLiteral originalSecret in originalSecrets)
        {
            string encodedValue = encoder(originalSecret.m_value);
            if (!string.IsNullOrEmpty(encodedValue) && encodedValue.Length >= MinimumSecretLength)
            {
                encodedSecrets.Add(new SecretLiteral(encodedValue));
            }
        }

        // Write section.
        try
        {
            m_lock.EnterWriteLock();

            // Add the encoder.
            _ = m_literalEncoders.Add(encoder);

            // Add the values.
            foreach (SecretLiteral encodedSecret in encodedSecrets)
            {
                _ = m_encodedSecretLiterals.Add(encodedSecret);
            }
        }
        finally
        {
            if (m_lock.IsWriteLockHeld)
            {
                m_lock.ExitWriteLock();
            }
        }
    }

    public ICollection<Detection> DetectSecrets(string input)
    {
        var detections = new List<Detection>();

        if (string.IsNullOrEmpty(input))
        {
            return detections;
        }

        if (RegexPatterns.Count == 0 &&
            m_explicitlyAddedSecretLiterals.Count == 0)
        {
            return detections;
        }

        // Read section.
        try
        {
            m_lock.EnterReadLock();
            var stopwatch = Stopwatch.StartNew();

            // Get indexes and lengths of all substrings that will be replaced.
            foreach (RegexPattern regexSecret in RegexPatterns)
            {
                var found = regexSecret.GetDetections(input, m_generateSha256Hashes);
                detections.AddRange(found);
            }

            foreach (SecretLiteral secretLiteral in m_encodedSecretLiterals)
            {
                var found = secretLiteral.GetDetections(input);
                detections.AddRange(found);
            }

            ElapsedMaskingTime += stopwatch.ElapsedTicks;
        }
        finally
        {
            if (m_lock.IsReadLockHeld)
            {
                m_lock.ExitReadLock();
            }
        }

        return detections;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    internal SecretMasker Clone()
    {
        return new SecretMasker(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !m_disposed)
        {
            m_lock.Dispose();
            m_disposed = true;
        }
    }

    private readonly bool m_generateSha256Hashes;
    private readonly HashSet<LiteralEncoder> m_literalEncoders;
    private readonly HashSet<SecretLiteral> m_encodedSecretLiterals;
    private readonly HashSet<SecretLiteral> m_explicitlyAddedSecretLiterals;
    private readonly ReaderWriterLockSlim m_lock = new(LockRecursionPolicy.NoRecursion);

    private bool m_disposed;
}
