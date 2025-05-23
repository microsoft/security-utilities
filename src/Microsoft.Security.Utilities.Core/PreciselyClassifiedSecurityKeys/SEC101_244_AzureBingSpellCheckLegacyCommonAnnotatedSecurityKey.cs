// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingSpellCheck)
    {
        Id = "SEC101/244";
        Name = nameof(AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Spell Check (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}