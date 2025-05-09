// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureImmersiveReader)
    {
        Id = "SEC101/219";
        Name = nameof(AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Immersive Reader (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}