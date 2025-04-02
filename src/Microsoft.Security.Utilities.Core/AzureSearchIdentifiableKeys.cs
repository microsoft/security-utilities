


// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.   

using System;

namespace Microsoft.Security.Utilities;

internal sealed class AzureSearchIdentifiableKeys : RegexPattern
{
    public static string GenerateQueryKeyTestExample()
    {
        return GenerateTestExample(IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed);
    }
    public static string GenerateAdminKeyTestExample()
    {
        return GenerateTestExample(IdentifiableMetadata.AzureSearchAdminKeyChecksumSeed);
    }

    private static string GenerateTestExample(ulong checksumSeed)
    {
        string key;
        while (true)
        {
            key = IdentifiableSecrets.GenerateStandardBase64Key(checksumSeed,
                                                                39,
                                                                IdentifiableMetadata.AzureSearchSignature);
#if NETCOREAPP3_1_OR_GREATER
            if (!key.Contains('+', StringComparison.Ordinal) && !key.Contains('/', StringComparison.Ordinal))
#else
            if (!key.Contains("+") && !key.Contains("/"))
#endif
            {
                return key;
            }
        }
    }
}