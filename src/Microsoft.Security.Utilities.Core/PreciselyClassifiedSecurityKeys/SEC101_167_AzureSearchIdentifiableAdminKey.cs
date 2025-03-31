// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureSearchIdentifiableAdminKey : AzureSearchIdentifiableQueryKey
    {
        public AzureSearchIdentifiableAdminKey()
        {
            Id = "SEC101/167";
            Name = nameof(AzureSearchIdentifiableAdminKey);
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureSearchAdminKeyChecksumSeed };
        }
    }
}
