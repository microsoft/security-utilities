// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;

#if NET
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
#endif
using System.Text;

namespace Microsoft.Security.Utilities;

/// <summary>
/// Internal data structure for textual input for secret masking/scaning. It is
/// backed by <see cref="ReadOnlyMemory{Char}" on modern .NET and by <see
/// cref="string"/> on legacy .NET Standard/Framework.
/// </summary>
internal readonly struct StringInput
{
    // Implementation notes:
    //
    // * Making this a ref struct and using ReadOnlySpan in place of
    //   ReadOnlyMemory would be better, but that requires significant
    //   additional refactoring due to pervasive use of iterators (yield
    //   return).
    //
    // * It is important that we do not retain the backing ReadOnlyMemory<char>
    //   beyond the end of a DetectSecrets or MaskSecrets call. The caller owns
    //   the memory. One of the disadvantages of using ReadOnlyMemory instead of
    //   ReadOnlySpan here is that this is not enforced by the compiler.
    //
    // * We could add dependencies to use Memory or Span on .NET
    //   Standard/Framework, but the regex API there does not support Memory or
    //   Span input, so we would still not be able to scan non-strings.
    //
    // * This type should remain internal. We should not add our own exchange
    //   type to represent textual input. This type should remain an
    //   implementation detail that exists to reduce the need for #if directives
    //   in the code base. It is very likely to change in the future.
#if NET
    public ReadOnlyMemory<char> Memory { get; }

    public ReadOnlySpan<char> Span => Memory.Span;

    public int Length => Memory.Length;

    public StringInput(string? value)
    {
        Memory = (value ?? string.Empty).AsMemory();
    }

    public StringInput(ReadOnlyMemory<char> value)
    {
        Memory = value;
    }

    public int IndexOf(ReadOnlySpan<char> value, StringComparison comparison)
    {
        return Span.IndexOf(value, comparison);
    }

    public int IndexOf(ReadOnlySpan<char> value, int startIndex, StringComparison comparison)
    {
        int index = Span.Slice(startIndex).IndexOf(value, comparison);
        return index < 0 ? index : index + startIndex;
    }

    public string Substring(int start, int length)
    {
        return Span.Slice(start, length).ToString();
    }

    public override string ToString()
    {
        return TryGetString(out string? str) ? str : Memory.ToString();
    }

    public bool TryGetString([NotNullWhen(true)] out string? str)
    {
        if (MemoryMarshal.TryGetString(Memory, out string? s,  out int start, out int length) &&
            start == 0 &&
            length == s.Length)
        {
            str = s;
            return true;
        }

        str = null;
        return false;
    }
#else
    public string String { get; }

    public int Length => String.Length;

    public StringInput(string? value)
    {
        String = value ?? string.Empty;
    }

    public int IndexOf(string value, StringComparison comparison)
    {
        return String.IndexOf(value, comparison);
    }

    public int IndexOf(string value, int startIndex, StringComparison comparison)
    {
        return String.IndexOf(value, startIndex, comparison);
    }

    public string Substring(int start, int length)
    {
        return String.Substring(start, length);
    }

    public override string ToString()
    {
        return String;
    }
#endif

    public static implicit operator StringInput(string? value)
    {
        return new StringInput(value);
    }
}

internal static class StringInputExtensions
{
    public static StringBuilder Append(this StringBuilder builder, StringInput input, int start, int length)
    {
#if NET
        return builder.Append(input.Span.Slice(start, length)); 
#else
        return builder.Append(input.String, start, length);
#endif
    }
}
