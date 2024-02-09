// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

internal class SecretLiteral
{
    public SecretLiteral(string value)
    {
        m_value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override Boolean Equals(Object obj)
    {
        var item = obj as SecretLiteral;
        if (item == null)
        {
            return false;
        }
        return string.Equals(m_value, item.m_value, StringComparison.Ordinal);
    }

    public override Int32 GetHashCode() => m_value.GetHashCode();

    public IEnumerable<Detection> GetDetections(string input)
    {
        if (!String.IsNullOrEmpty(input) && !String.IsNullOrEmpty(m_value))
        {
            Int32 startIndex = 0;
            while (startIndex > -1 &&
                   startIndex < input.Length &&
                   input.Length - startIndex >= m_value.Length) // remaining substring longer than secret value
            {
                startIndex = input.IndexOf(m_value, startIndex, StringComparison.Ordinal);
                if (startIndex > -1)
                {
                    yield return new Detection(null, null, startIndex, m_value.Length, 0);
                    ++startIndex;
                }
            }
        }
    }

    internal readonly String m_value;
}