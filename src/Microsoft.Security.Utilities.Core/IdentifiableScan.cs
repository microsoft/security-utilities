// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that can scan data for identifiable secrets.
/// </summary>
public class IdentifiableScan : ISecretMasker, IDisposable
{
    private bool generateCorrelatingIds;

    [DllImport("microsoft_security_utilities_core")]
    static extern IntPtr identifiable_scan_create(
         byte[] filter,
         long filterLength);

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
    static extern UInt32 identifiable_scan_match_count(IntPtr scan);

    [DllImport("microsoft_security_utilities_core")]
    static extern UInt32 identifiable_scan_def_count(IntPtr scan);

    [DllImport("microsoft_security_utilities_core")]
    static extern void identifiable_scan_def_name(
        IntPtr scan,
        UInt32 index,
        byte[] name,
        ref long nameLength);

    [DllImport("microsoft_security_utilities_core")]
    static extern bool identifiable_scan_match_get(
        IntPtr scan,
        UInt32 index,
        out UInt64 start,
        out UInt64 len);

    [DllImport("microsoft_security_utilities_core")]
    static extern bool identifiable_scan_match_check(
        IntPtr scan,
        UInt32 index,
        byte[] input,
        long inputLength,
        out UInt32 defIndex,
        byte[] output,
        ref long outputLength);

    private IntPtr scan;
    private Dictionary<string, IList<RegexPattern>> idToLengthMap;
    private List<string> indexToIdMap;

    [ThreadStatic]
    static StringBuilder stringBuilder;
    
    public IdentifiableScan(IEnumerable<RegexPattern> regexPatterns, bool generateCorrelatingIds)
    {   
        this.generateCorrelatingIds = generateCorrelatingIds;
        this.idToLengthMap = new Dictionary<string, IList<RegexPattern>>();
        this.indexToIdMap = new List<string>();

        // TODO: This is missing in regexPatterns.
        this.idToLengthMap["SEC101/200"] = new List<RegexPattern>
        {
            new RegexPattern(
                "SEC101/200",
                "AzureCommonAnnotatedSecurityKey",
                DetectionMetadata.None,
                "JQQJ")
        };

        foreach (RegexPattern pattern in regexPatterns)
        {
            foreach (string spnSignature in new[] { "7Q~", "8Q~" })
            {
                if (pattern.SniffLiterals?.FirstOrDefault() == spnSignature)
                {
                    this.idToLengthMap["SEC101/156"] = new List<RegexPattern> { pattern };
                    continue;
                }
            }

            IIdentifiableKey identifiableKey = pattern as IIdentifiableKey;
            if (identifiableKey == null) { continue; }

            if (!this.idToLengthMap.TryGetValue(identifiableKey.Id, out IList<RegexPattern> patterns))
            {
                patterns = new List<RegexPattern>();
                this.idToLengthMap[identifiableKey.Id] = patterns;
            }

            patterns.Add(pattern);
        }
    }

    public UInt32 PossibleMatches
    {
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
            stringBuilder ??= new StringBuilder();
            stringBuilder.Clear();

            foreach (var id in this.idToLengthMap.Keys)
            {
                stringBuilder.Append(id);
                stringBuilder.Append(';');
            }

            var filter = Encoding.UTF8.GetBytes(stringBuilder.ToString());

            this.scan = identifiable_scan_create(filter, filter.Length);

            if (this.scan == IntPtr.Zero)
            {
                throw new OutOfMemoryException();
            }

            UInt32 defCount = identifiable_scan_def_count(this.scan);
            byte[] nameBytes = ArrayPool<byte>.Shared.Rent(256);

            this.indexToIdMap.Clear();

            for (UInt32 i = 0; i < defCount; ++i)
            {
                long length = nameBytes.Length;

                identifiable_scan_def_name(this.scan,
                                           i,
                                           nameBytes,
                                           ref length);

                var name = Encoding.UTF8.GetString(nameBytes, 0, (int)length);

                this.indexToIdMap.Add(name);
            }

            ArrayPool<byte>.Shared.Return(nameBytes);
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

    public bool GetPossibleMatchRange(UInt32 index, out UInt64 start, out UInt64 len)
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

    public string CheckPossibleMatchRange(
        UInt32 index,
        byte[] input,
        long inputLength,
        byte[] output,
        out long copiedLength)
    {
        long outputLen = 0;
        copiedLength = 0;

        if (this.scan == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Start() must be called before scanning.");
        }

        if (output != null)
        {
            outputLen = output.Length;
        }

        UInt32 defIndex;
        string name = string.Empty;

        if (identifiable_scan_match_check(
            this.scan,
            index,
            input,
            inputLength,
            out defIndex,
            output,
            ref outputLen))
        {
            if (defIndex < this.indexToIdMap.Count)
            {
                name = this.indexToIdMap[(int)defIndex];
            }

            copiedLength = outputLen;
        }

        return name;
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(input));

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

        for (UInt32 i = 0; i < PossibleMatches; ++i)
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

                var name = CheckPossibleMatchRange(i,
                                                   buffer,
                                                   copied,
                                                   text,
                                                   out textLength);

                if (name.Length != 0)
                {
                    if (idToLengthMap.TryGetValue(name, out IList<RegexPattern> patterns))
                    {
                        string found = System.Text.Encoding.UTF8.GetString(text, 0, (int)textLength);

                        foreach (RegexPattern pattern in patterns)
                        {
                            string redactionToken = null;

                            if (generateCorrelatingIds)
                            {
                               redactionToken = RegexPattern.GenerateCrossCompanyCorrelatingId(found);
                            }

                            yield return new Detection
                            {
                                Id = pattern.Id,
                                Name = pattern.Name,
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
