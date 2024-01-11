// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading;

namespace Microsoft.Security.Utilities;

#nullable enable

#pragma warning disable CA1846  // Prefer 'AsSpan' over 'Substring'.
#pragma warning disable CA1852 // Seal internal types
#pragma warning disable IDE1006 // Naming rule violation.

internal class SecretMasker : ISecretMasker, IDisposable
{
    public SecretMasker(IEnumerable<RegexPattern>? regexSecrets, bool generateSha256Hashes = false)
    {
        m_disposed = false;

        RegexPatterns = regexSecrets != null
            ? new HashSet<RegexPattern>(regexSecrets)
            : new HashSet<RegexPattern>();

        m_generateSha256Hashes = generateSha256Hashes;
    }

    public SecretMasker()
        : this(new HashSet<RegexPattern>())
    {
    }

    [ThreadStatic]
    private static StringBuilder? s_stringBuilder;

    public virtual HashSet<RegexPattern> RegexPatterns { get; protected set; }

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

    public string? MaskSecrets(string input)
    {
        if (input == null)
        {
            return null;
        }

        var detections = DetectSecrets(input);

        // Short-circuit if nothing to replace.
        if (detections.Count == 0)
        {
            return input;
        }

        // Merge positions into ranges of characters to replace.
        Detection currentDetection = default;
        foreach (Detection secretPosition in detections.OrderBy(x => x.Start))
        {
            if (currentDetection.Equals(default))
            {
                detections.Add(secretPosition);
            }
            else
            {
                if (secretPosition.Start <= currentDetection.End)
                {
                    // Overlapping case.
                    currentDetection =
                        new Detection(currentDetection.Id,
                                      currentDetection.Name,
                                      currentDetection.Start,
                                      Math.Max(currentDetection.End, secretPosition.End) - currentDetection.Start,
                                      currentDetection.Metadata,
                                      currentDetection.RotationPeriod,
                                      currentDetection.Sha256Hash,
                                      currentDetection.RedactionToken);
                }
                else
                {
                    // No overlap
                    detections.Add(secretPosition);
                }
            }
        }

        s_stringBuilder ??= new StringBuilder();
        s_stringBuilder.Length = 0;

        int startIndex = 0;
        foreach (var detection in detections)
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

    public ICollection<Detection> DetectSecrets(string input)
    {
        if (RegexPatterns == null || RegexPatterns.Count == 0)
        {
            throw new InvalidOperationException("Masker has not been initialized with any patterns.");
        }

        var detections = new List<Detection>();

        if (string.IsNullOrEmpty(input))
        {
            return detections;
        }

        // Read section.
        try
        {
            m_lock.EnterReadLock();

            // Get indexes and lengths of all substrings that will be replaced.
            foreach (RegexPattern regexSecret in RegexPatterns)
            {
                var found = regexSecret.GetDetections(input, m_generateSha256Hashes);
                detections.AddRange(found);
            }
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

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !m_disposed)
        {
            m_lock.Dispose();
            m_disposed = true;
        }
    }

    private readonly bool m_generateSha256Hashes;
    private ReaderWriterLockSlim m_lock = new(LockRecursionPolicy.NoRecursion);
    private bool m_disposed;
}
