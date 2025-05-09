// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public abstract class CognitiveServiceLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    protected CognitiveServiceLegacyCommonAnnotatedSecurityKey(AzureCognitiveServices service)
        : base(providerData: $"AAA{CustomAlphabetEncoder.DefaultBase64Alphabet[(int)service]}")
    {
        AzureCognitiveService = service;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureCognitiveServices;

    protected AzureCognitiveServices AzureCognitiveService { get; }

    public override Tuple<string, string> GetMatchIdAndName(string match)
    {
        if (match.Length == 88) // comment or constant please
        {
            return null;
        }

        return base.GetMatchIdAndName(match);
    }
}