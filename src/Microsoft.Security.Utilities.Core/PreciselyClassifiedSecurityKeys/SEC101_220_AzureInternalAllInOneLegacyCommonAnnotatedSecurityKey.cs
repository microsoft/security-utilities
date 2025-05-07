// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/220";
        Name = nameof(AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Internal All-In-One (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureInternalAllInOne;
}