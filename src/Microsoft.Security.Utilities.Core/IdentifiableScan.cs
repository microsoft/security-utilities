// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that can scan data for identifiable secrets.
/// </summary>
public class IdentifiableScan: IDisposable
{
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
}
