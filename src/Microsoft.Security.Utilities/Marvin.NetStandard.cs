﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if NETSTANDARD2_0_OR_GREATER

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    /// This version of Marvin was obtained from a recent archive of the .NET core runtime.
    /// This particular implementation is highly compatible with recent versions of .NET,
    /// without utilizing leading edge C#/framework features.
    /// https://github.com/dotnet/corert/blob/c6af4cfc8b625851b91823d9be746c4f7abdc667/src/Common/src/System/Marvin.cs
    /// </summary>
    public static class Marvin
    {
        /// <summary>
        /// Convenience method to compute a Marvin hash and collapse it into a 32-bit hash.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ComputeHash32(ReadOnlySpan<byte> data, ulong seed)
        {
            long hash64 = ComputeHash(data, seed);
            return ((int)(hash64 >> 32)) ^ (int)hash64;
        }

        /// <summary>
        /// Computes a 64-bit hash using the Marvin algorithm.
        /// </summary>
        public static long ComputeHash(ReadOnlySpan<byte> data, ulong seed)
        {
            uint p0 = (uint)seed;
            uint p1 = (uint)(seed >> 32);

            if (data.Length >= sizeof(uint))
            {
                ReadOnlySpan<uint> uData = MemoryMarshal.Cast<byte, uint>(data);

                for (int i = 0; i < uData.Length; i++)
                {
                    p0 += uData[i];
                    Block(ref p0, ref p1);
                }

                // byteOffset = data.Length - data.Length % 4
                // is equivalent to clearing last 2 bits of length
                // Using it directly gives a perf hit for short strings making it at least 5% or more slower.
                int byteOffset = data.Length & (~3);

                // More recent versions of C# support index and range operators such as the following...
                //data = data[byteOffset..];

                data = data.Slice(byteOffset);
            }

            switch (data.Length)
            {
                case 0:
                    p0 += 0x80u;
                    break;

                case 1:
                    p0 += 0x8000u | data[0];
                    break;

                case 2:
                    p0 += 0x800000u | MemoryMarshal.Cast<byte, ushort>(data)[0];
                    break;

                case 3:
                    p0 += 0x80000000u | (((uint)data[2]) << 16) | (uint)(MemoryMarshal.Cast<byte, ushort>(data)[0]);
                    break;

                default:
                    Debug.Fail("Should not get here.");
                    break;
            }

            Block(ref p0, ref p1);
            Block(ref p0, ref p1);

            return (((long)p1) << 32) | p0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Block(ref uint rp0, ref uint rp1)
        {
            uint p0 = rp0;
            uint p1 = rp1;

            p1 ^= p0;
            p0 = Rotate(p0, 20);

            p0 += p1;
            p1 = Rotate(p1, 9);

            p1 ^= p0;
            p0 = Rotate(p0, 27);

            p0 += p1;
            p1 = Rotate(p1, 19);

            rp0 = p0;
            rp1 = p1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Rotate(uint value, int shift)
        {
            // This is expected to be optimized into a single rol (or ror with negated shift value) instruction
            return (value << shift) | (value >> (32 - shift));
        }
    }
}

#endif
