﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureEventGridIdentifiableKey : CommonAnnotatedSecurityKey
    {
        public AzureEventGridIdentifiableKey()
        {
            Id = "SEC101/190";
            Name = nameof(AzureEventGridIdentifiableKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureEventGridSignature.ToSet();
    }
}
