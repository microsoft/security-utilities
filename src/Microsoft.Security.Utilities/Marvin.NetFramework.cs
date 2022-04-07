// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#if NET45_OR_GREATER

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    /// This is a C# implementation of the Marvin32 checksum algorithm, the definite native code for which is
    /// at https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c. This C# version is based on an
    /// implementation included in .NET, which is used to produce GetHashCode() values for strings, the code
    /// for which is at https://github.com/dotnet/corert/blob/master/src/Common/src/System/Marvin.cs. This
    /// version was selected for use as it has fewer uses of types and C# language constructs that are not
    /// compatible with .NET 4.5 (which is required for this project). The code has been further modified
    /// based on the .NET 4.5 compatibility constraint to remove use of ReadOnlySpan<T>.
    ///
    /// The most recent version of this algorithm, if helpful in the future, is located at:
    /// https://github.com/dotnet/runtime/blob/57bfe474518ab5b7cfe6bf7424a79ce3af9d6657/src/libraries/System.Private.CoreLib/src/System/Marvin.cs
    /// </summary>
    public static class Marvin
    {
        /// <summary>
        /// Convenience method to compute a Marvin hash and collapse it into a 32-bit hash.
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <param name="seed">A seed provided to the checksum implementation that helps randomize results
        /// <param name="offset">The offset from which to compute the checksum.</param>
        /// <param name="length">The number of bytes to checksum.</param>
        /// and ensures that checksums for shorter data buffers aren't constrained to less than 64 bits.</param>
        /// <returns>The computed Marvin32 64-bit checksum of the input data collapsed into a 32-bit value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ComputeHash32(byte[] data, ulong seed, int offset, int length)
        {
            long hash64 = ComputeHash(data, seed, offset, length);
            return ((int)(hash64 >> 32)) ^ (int)hash64;
        }

        /// <summary>
        /// Computes a 64-bit hash using the Marvin algorithm.
        /// </summary>
        /// <param name="data">The data to be hashed.</param>
        /// <param name="seed">A seed provided to the checksum implementation that helps randomize results
        /// and ensures that checksums for shorter data buffers aren't constrained to less than 64 bits.</param>
        /// <param name="offset">The offset from which to compute the checksum.</param>
        /// <param name="length">The number of bytes to checksum.</param>
        /// <returns>The computed Marvin32 64-bit checksum of the input data.</returns>
        public static long ComputeHash(byte[] data, ulong seed, int offset, int length)
        {
            // Marvin by design can produce a checksum for empty input buffers, which
            // is why it's ok for the offset to point just past the end of the buffer
            // or for the input buffer to be empty;
            if (offset < 0 || offset > data.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            if ((offset + length) > data.Length)
            {
                throw new ArgumentOutOfRangeException();
            }

            uint p0 = (uint)seed;
            uint p1 = (uint)(seed >> 32);

            unsafe
            {
                int remainingDataOffset = 0;
                fixed (byte* d = data)
                {
                    int uintCount = length / 4;
                    if (length >= sizeof(uint))
                    {
                        int index = 0 + offset;
                        for (int i = 0; i < uintCount; i++)
                        {
                            fixed (byte* b = &data[index])
                            {
                                p0 += *(uint*)b;
                            }

                            Block(ref p0, ref p1);
                            index += 4;
                        }

                        // byteOffset = data.Length - data.Length % 4
                        // is equivalent to clearing last 2 bits of length
                        // Using it directly gives a perf hit for short strings making it at least 5% or more slower.
                        remainingDataOffset = length & (~3);
                        length -= remainingDataOffset;
                    }

                    remainingDataOffset += offset;

                    switch (length)
                    {
                        case 0:
                            p0 += 0x80u;
                            break;

                        case 1:
                            p0 += 0x8000u | data[remainingDataOffset];
                            break;

                        case 2:
                            fixed (byte* pb0 = &data[remainingDataOffset])
                            {
                                p0 += 0x800000u | *(ushort*)pb0;
                            }

                            break;

                        case 3:
                            fixed (byte* pb0 = &data[remainingDataOffset], pb2 = &data[remainingDataOffset + 2])
                            {
                                p0 += 0x80000000u | ((uint)(*(byte*)pb2) << 16) | (uint)*(ushort*)pb0;
                            }

                            break;

                        default:
                            Debug.Fail("Should not get here.");
                            break;
                    }
                }
            }

            Block(ref p0, ref p1);
            Block(ref p0, ref p1);

            return (((long)p1) << 32) | p0;
        }

        /// <summary>
        /// Combines hash code of multiple objects while trying to minimize possibility of collisions.
        /// </summary>
        /// <param name="rp0">Hash code seed.</param>
        /// <param name="rp1">Delegates to generate hash codes to combine.</param>
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

        /// <summary>
        /// Shift bits in an unsigned integer.
        /// </summary>
        /// <param name="value">Unsigned integer to left- or right-rotate.</param>
        /// <param name="shift">The number of bits to rotate right or left.</param>
        /// <returns>Rotated unsigned value.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Rotate(uint value, int shift)
        {
            // This is expected to be optimized into a single rol (or ror with negated shift value) instruction
            return (value << shift) | (value >> (32 - shift));
        }
    }
}

#endif
