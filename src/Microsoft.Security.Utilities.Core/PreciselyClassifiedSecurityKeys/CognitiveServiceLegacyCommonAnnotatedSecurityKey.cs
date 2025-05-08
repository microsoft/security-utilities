// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public abstract class CognitiveServiceLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureCognitiveServices;

    protected abstract AzureCognitiveServices AzureCognitiveService { get; }

    protected override string ProviderData => $"AAA{CustomAlphabetEncoder.DefaultBase64Alphabet[(int)AzureCognitiveService]}";

    public override Tuple<string, string> GetMatchIdAndName(string match)
    {
        if (match.Length == 88)
        {
            return null;
        }

        if (!LegacyCommonAnnotatedSecurityKey.TryCreate(match, out var legacyCask))
        {
            return null;
        }

        if (legacyCask.ProviderFixedSignature != ProviderSignature)
        {
            return null;
        }

        if (legacyCask.ProviderReserved != ProviderData)
        {
            return null;
        }

        return new Tuple<string, string>(Id, Name);
    }
}