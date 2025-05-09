// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureCognitiveServices)
    {
        Id = "SEC101/209";
        Name = nameof(AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey);
        Label = "a general Azure Cognitive Services legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}