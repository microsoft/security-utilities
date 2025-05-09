// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureDummyLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureDummyLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureDummy)
    {
        Id = "SEC101/233";
        Name = nameof(AzureDummyLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Dummy (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}