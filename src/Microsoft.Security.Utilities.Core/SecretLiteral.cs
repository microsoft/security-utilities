﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public class SecretLiteral
{
    public const string FallbackRedactionToken = "***";

    public SecretLiteral(string value)
    {
        m_value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public override bool Equals(object? obj)
    {
        var item = obj as SecretLiteral;
        if (item == null)
        {
            return false;
        }
        return string.Equals(m_value, item.m_value, StringComparison.Ordinal);
    }

    public override int GetHashCode() => m_value.GetHashCode();

    public IEnumerable<Detection> GetDetections(string input, string redactionToken)
    {
        if (string.IsNullOrWhiteSpace(redactionToken))
        {
            redactionToken = FallbackRedactionToken;
        }

        if (!string.IsNullOrEmpty(input) && !string.IsNullOrEmpty(m_value))
        {
            int startIndex = 0;
            while (startIndex > -1 &&
                   startIndex < input.Length &&
                   input.Length - startIndex >= m_value.Length) // remaining substring longer than secret value
            {
                startIndex = input.IndexOf(m_value, startIndex, StringComparison.Ordinal);
                if (startIndex > -1)
                {
                    yield return new Detection(id: null,
                                               name: null,
                                               start: startIndex,
                                               length: m_value.Length,
                                               metadata: 0,
                                               rotationPeriod: default,
                                               crossCompanyCorrelatingId: null,
                                               redactionToken);
                    ++startIndex;
                }
            }
        }
    }

    internal readonly string m_value;
}