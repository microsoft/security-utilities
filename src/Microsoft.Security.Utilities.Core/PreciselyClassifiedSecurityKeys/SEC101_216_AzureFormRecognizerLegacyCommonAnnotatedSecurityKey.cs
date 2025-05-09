// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureFormRecognizerLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureFormRecognizerLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureFormRecognizer)
    {
        Id = "SEC101/216";
        Name = nameof(AzureFormRecognizerLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Form Recognizer (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}