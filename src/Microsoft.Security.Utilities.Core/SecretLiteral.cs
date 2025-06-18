// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

internal readonly record struct SecretLiteral
{
    public const string FallbackRedactionToken = "***";

    public SecretLiteral(string value)
    {
        Value = value ?? throw new ArgumentNullException(nameof(value));
    }

    public IEnumerable<Detection> GetDetections(StringInput input, string redactionToken)
    {
        if (string.IsNullOrWhiteSpace(redactionToken))
        {
            redactionToken = FallbackRedactionToken;
        }

        if (input.Length > 0 && !string.IsNullOrEmpty(Value))
        {
            int startIndex = 0;
            while (startIndex > -1 &&
                   startIndex < input.Length &&
                   input.Length - startIndex >= Value.Length) // remaining substring longer than secret value
            {
                startIndex = input.IndexOf(Value, startIndex, StringComparison.Ordinal);
                if (startIndex > -1)
                {
                    yield return new Detection(id: null,
                                               name: null,
                                               label: null,
                                               start: startIndex,
                                               length: Value.Length,
                                               metadata: 0,
                                               rotationPeriod: default,
                                               crossCompanyCorrelatingId: null,
                                               redactionToken,
                                               kind: DetectionKind.Literal);
                    ++startIndex;
                }
            }
        }
    }

    public string Value { get; }
}