// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that can scan data for identifiable secrets.
/// </summary>
public class IdentifiableScan : ISecretMasker, IDisposable
{
    private bool generateCorrelatingIds;

    public enum MatchType: ushort
    {
        None = 0,
        U32Utf8 = 1,
        U32Utf16 = 2,
        U64Utf8 = 3,
        U64Utf16 = 4,
        Utf8 = 5,
        Utf16 = 6,
        Unknown = 7,
    }

    [DllImport("microsoft_security_utilities_core")]
    static extern IntPtr identifiable_scan_create();

    [DllImport("microsoft_security_utilities_core")]
    static extern void identifiable_scan_destroy(IntPtr scan);

    [DllImport("microsoft_security_utilities_core")]
    static extern void identifiable_scan_start(IntPtr scan);

    [DllImport("microsoft_security_utilities_core")]
    static extern bool identifiable_scan_parse(
        IntPtr scan,
        byte[] bytes,
        long len);

    [DllImport("microsoft_security_utilities_core")]
    static extern long identifiable_scan_match_count(IntPtr scan);

    [DllImport("microsoft_security_utilities_core")]
    static extern bool identifiable_scan_match_get(
        IntPtr scan,
        long index,
        out UInt64 start,
        out UInt64 len);

    [DllImport("microsoft_security_utilities_core")]
    static extern bool identifiable_scan_match_check(
        IntPtr scan,
        long index,
        byte[] input,
        long inputLength,
        out ushort matchType,
        byte[] output,
        long outputLength,
        out long copiedLength);

    private IntPtr scan;
    private Dictionary<string, IList<RegexPattern>> signatureToLengthMap;
    
    public IdentifiableScan(IEnumerable<RegexPattern> regexPatterns, bool generateCorrelatingIds)
    {   
        this.generateCorrelatingIds = generateCorrelatingIds;
        this.signatureToLengthMap = new Dictionary<string, IList<RegexPattern>>();

        foreach (RegexPattern pattern in regexPatterns)
        {
            IIdentifiableKey identifiableKey = pattern as IIdentifiableKey;
            if (identifiableKey == null) { continue; }

            if (!this.signatureToLengthMap.TryGetValue(identifiableKey.Signature, out IList<RegexPattern> patterns))
            {
                patterns = new List<RegexPattern>();
                this.signatureToLengthMap[identifiableKey.Signature] = patterns;
            }

            patterns.Add(pattern);
        }   
    }

    public long PossibleMatches {
        get
        {
            if (this.scan != IntPtr.Zero)
            {
                return identifiable_scan_match_count(this.scan);
            }

            return 0;
        }
    }

    public void Dispose()
    {
        if (this.scan != IntPtr.Zero)
        {
            identifiable_scan_destroy(this.scan);

            this.scan = IntPtr.Zero;
        }
    }

    public void Start()
    {
        if (this.scan == IntPtr.Zero)
        {
            this.scan = identifiable_scan_create();

            if (this.scan == IntPtr.Zero)
            {
                throw new OutOfMemoryException();
            }
        }

        identifiable_scan_start(this.scan);
    }

    public bool Scan(byte[] bytes, long len)
    {
        if (this.scan == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Start() must be called before scanning.");
        }

        return identifiable_scan_parse(this.scan, bytes, len);
    }

    public bool GetPossibleMatchRange(long index, out UInt64 start, out UInt64 len)
    {
        start = 0;
        len = 0;

        if (this.scan == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Start() must be called before scanning.");
        }

        return identifiable_scan_match_get(this.scan, index, out start, out len);
    }

    public MatchType CheckPossibleMatchRange(
        long index,
        byte[] input,
        long inputLength,
        byte[] output,
        out long copiedLength)
    {
        long outputLen = 0;

        if (this.scan == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Start() must be called before scanning.");
        }

        if (output != null)
        {
            outputLen = output.Length;
        }

        MatchType type = MatchType.None;
        ushort matchType = 0;

        if (identifiable_scan_match_check(
            this.scan,
            index,
            input,
            inputLength,
            out matchType,
            output,
            outputLen,
            out copiedLength))
        {
            if (matchType < (ushort)MatchType.Unknown)
            {
                type = (MatchType)matchType;
            }
        }

        return type;
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        using var stream = new MemoryStream(Encoding.Unicode.GetBytes(input));

        foreach (var detection in DetectSecrets(stream))
        {
            yield return detection;
        }
    }

    public IEnumerable<Detection> DetectSecrets(Stream file)
    {
        var buffer = new byte[85 * 1024];
        var text = new byte[256];

        Start();

        for (; ; )
        {
            var read = file.Read(buffer, 0, buffer.Length);

            if (read == 0)
            {
                break;
            }

            Scan(buffer, read);
        }

        if (PossibleMatches == 0)
        {
            yield break;
        }

        for (var i = 0; i < PossibleMatches; ++i)
        {
            UInt64 start, len;

            if (GetPossibleMatchRange(i,
                                      out start,
                                      out len))
            {
                file.Seek((long)start, SeekOrigin.Begin);

                var remaining = (int)len;
                var copied = 0;

                while (remaining > 0)
                {
                    var read = file.Read(buffer, (int)copied, (int)remaining);

                    if (read == 0)
                    {
                        break;
                    }

                    copied += read;
                    remaining -= read;
                }

                long textLength;

                var type = CheckPossibleMatchRange(i,
                                                   buffer,
                                                   copied,
                                                   text,
                                                   out textLength);

                if (type != IdentifiableScan.MatchType.None)
                {
                    var secret = System.Text.Encoding.UTF8.GetString(text, 0, (int)textLength);
                    
                    int equalSignIndex = secret.IndexOf('=');
                    int toTrim = equalSignIndex == -1 ? secret.Length : equalSignIndex;
                    
                    string signature = secret.Substring(toTrim - 10, 4);

                    if (signatureToLengthMap.TryGetValue(signature, out IList<RegexPattern> patterns))
                    {
                        foreach (RegexPattern pattern in patterns)
                        {
                            var tuple = pattern.GetMatchIdAndName(secret);
                            if (tuple == default) { continue; }

                            string redactionToken = this.generateCorrelatingIds
                                ? RegexPattern.GenerateCrossCompanyCorrelatingId(secret)
                                : null;

                            yield return new Detection
                            {
                                Id = tuple.Item1,
                                Name = tuple.Item2,
                                Start = (int)start,
                                Length = (int)textLength,
                                RedactionToken = redactionToken,
                            };
                        }
                    }
                }
            }
        }
    }

    public string MaskSecrets(string input)
    {
        throw new NotImplementedException();
    }
}
