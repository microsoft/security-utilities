// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public abstract class CognitiveServiceLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    protected CognitiveServiceLegacyCommonAnnotatedSecurityKey(AzureCognitiveService service)
        : base(providerData: $"AAA{CustomAlphabetEncoder.DefaultBase64Alphabet[(int)service]}")
    {
        AzureCognitiveService = service;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureCognitiveServices;

    protected AzureCognitiveService AzureCognitiveService { get; }

    public override Tuple<string, string> GetMatchIdAndName(string match)
    {
        // No Cognitive Services provider supports a long-form key and so we can
        // reject any matches that are 88 characters long. We can't push this check
        // into the base class because the legacy CASK format permits long-form
        // (88 character) access keys for other cases.
        if (match.Length == 88)
        {
            return null;
        }

        return base.GetMatchIdAndName(match);
    }
}