// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1501  // Statement should not be on a single line.

/// <summary>
/// This class contains resource provider signatures and checksum seeds that
/// are used to drive highly identifiable secret (HIS) generation. This data
/// is co-located as it is useful to bundle all the information for
/// resource provider in the same place (as well as noting the internal pull
/// requests that provide pointers to definitive data and implementation
/// details.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class IdentifiableMetadata
{
    public const string AzureEventGridSignature = "AZEG";

    public const string AzureServiceBusSignature = "+ASb";
    public const string AzureEventHubSignature = "+AEh";
    public const string AzureRelaySignature = "+ARm";
    public const ulong AzureServiceBusOrEventHubSystemKeySeed = 0x53797374656d3030;
    public const ulong AzureMessagingUnknownSeed = 0x556e6b6e6f776e30;
    public const ulong AzureMessagingSendKeyChecksumSeed = 0x53656e6430303030;
    public const ulong AzureMessagingManageKeyChecksumSeed = 0x4d616e6167653030;
    public const ulong AzureMessagingListenKeyChecksumSeed = 0x4c697374656e3030;

    public const string AzureBatchSignature = "+ABa";
    public const ulong AzureBatchChecksumSeed = 0x4162416363743030;

    public const string AzureFunctionSignature = "AzFu";
    public const ulong AzureFunctionMasterKeyChecksumSeed = 0x4d61737465723030;
    public const ulong AzureFunctionSystemKeyChecksumSeed = 0x53797374656d3030;
    public const ulong AzureFunctionKeyChecksumSeed = 0x46756e6374693030;

    public const string AzureCosmosDBSignature = "ACDb";
    public const ulong AzureCosmosDBSystemAllChecksumSeed = 0x537973416c6c3030;
    public const ulong AzureCosmosDBResourceKeySeedChecksumSeed = 0x5265736f75723030;
    public const ulong AzureCosmosDBMasterReadOnlyKeyChecksumSeed = 0x4d617374524f3030;
    public const ulong AzureCosmosDBSystemReadOnlyKeyChecksumSeed = 0x53797374524f3030;
    public const ulong AzureCosmosDBDataEncryptionKeyChecksumSeed = 0x456e637279703030;
    public const ulong AzureCosmosDBMasterReadWriteKeyChecksumSeed = 0x4d61737452573030;
    public const ulong AzureCosmosDBSystemReadWriteKeyChecksumSeed = 0x5379737452573030;

    public const string AzureCacheForRedisSignature = "AzCa";
    public const ulong AzureCacheForRedisChecksumSeed = 0x4163636573733030;

    public const string AzureStorageSignature = "+ASt";
    public const ulong AzureStorageAccountChecksumSeed = 0x44656661756c7430;

    public const string AadClientAppLegacySignature = "7Q~";
    public const string AadClientAppCurrentSignature = "8Q~";
    public const ulong AadClientAppChecksumSeed = 0x4161645077643030;
    public const string AadClientPasswordCharacterSet =
        "abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "1234567890" +
        ".-_~";

    public const string AzureSearchSignature = "AzSe";
    public const ulong AzureSearchQueryKeyChecksumSeed = 0x5175657279303030;
    public const ulong AzureSearchAdminKeyChecksumSeed = 0x5041646d696e3030;

    public const string AzureMLClassicSignature = "+AMC";
    public const ulong AzureMLClassicChecksumSeed = 0x436c617373696330;

    public const string AzureMLSignature = "/AM7";

    public const uint AdoUserPatChecksumSeed = 0xE0B9692D;
    public const uint AdoApplicationPatChecksumSeed = 0x1019F92E;

    // https://msazure.visualstudio.com/One/_git/DevServices-ContainerRegistry-Service/pullrequest/6036091
    public const string AzureContainerRegistrySignature = "+ACR";
    public const ulong AzureContainerRegistryChecksumSeed = 0x41435244666c7430;

    public const string SqlIdentifiableSignature = "+SQL";
    public const ulong SqlIdentifiableChecksumSeed = 0x5573725077643030;

    public const string AzureIotSignature = "AIoT";
    public const ulong AzureIotHubChecksumSeed = 0x496f544875623030;
    public const ulong AzureIotDeviceProvisioningChecksumSeed = 0x4470734b65793030;
    public const ulong AzureIotDeviceChecksumSeed = 0x4465766963653030;

    public const string AzureApimSignature = "APIM";
    public const ulong AzureApimDirectManagementChecksumSeed = 0x54656e616e743030;
    public const ulong AzureApimSubscriptionChecksumSeed = 0x496f544875623030;
    public const ulong AzureApimGatewayChecksumSeed = 0x4761746577793030;
    public const ulong AzureApimRepositoryChecksumSeed = 0x4769744b65793030;

    public static bool IsAzureAadClientAppIdentifiableSecret(string secret)
    {
        var encoder = new CustomAlphabetEncoder(AadClientPasswordCharacterSet);
        int secretLength = secret.Length;

        string signature = secret.Substring(3, AadClientAppLegacySignature.Length);

        // For secrets with '7Q~' signature, we don't have checksum verification.
        if (signature == AadClientAppLegacySignature)
        {
            return true;
        }

        // Only run checksum analysis on secrets with '8Q~' signature
        if (signature != AadClientAppCurrentSignature)
        {
            return false;
        }

        // The current AAD client app password allocation code persists the first
        // 3 characters (of 6) of the checksum only, in order to minimize the
        // length increase of the generated secret.
        string checksumPrefix = secret.Substring(secretLength - 3);
        string textToChecksum = secret.Substring(0, secretLength - 3);

        // https://en.wikipedia.org/wiki/ISO/IEC_8859-1
        // We are encoding a subset of ANSI, and Latin1
        // is reasonable approximation of the character
        // set we expect.
        var latin1Encoding = Encoding.GetEncoding("ISO-8859-1");
        byte[] input = latin1Encoding.GetBytes(textToChecksum);

#if !NET5_0_OR_GREATER
        int checksum = Marvin.ComputeHash32(input, AadClientAppChecksumSeed, 0, input.Length);
#else
        int checksum = Marvin.ComputeHash32(input, AadClientAppChecksumSeed);
#endif
        string encodedChecksum = encoder.Encode((uint)checksum);

        return
            encodedChecksum[0] == checksumPrefix[0] &&
            encodedChecksum[1] == checksumPrefix[1] &&
            encodedChecksum[2] == checksumPrefix[2];
    }

    public static bool IsAzureBatchIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureBatchChecksumSeed,
                                                         AzureBatchSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureCacheForRedisIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureCacheForRedisChecksumSeed,
                                                         AzureCacheForRedisSignature) ||
                                                         AzureCacheForRedisWithSpecialCharacterChecksum(secret, AzureCacheForRedisChecksumSeed);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureCosmosDBIdentifiableKey(string secret)
    {
        ulong[] checksumSeeds = new[]
        {
            AzureCosmosDBMasterReadOnlyKeyChecksumSeed,
            AzureCosmosDBMasterReadWriteKeyChecksumSeed,
        };

        foreach (ulong checksumSeed in checksumSeeds)
        {
            try
            {
                if (IdentifiableSecrets.ValidateBase64Key(secret,
                                                          checksumSeed,
                                                          AzureCosmosDBSignature))
                {
                    return true;
                }
            }
            catch (FormatException) { return false; }
        }

        return false;
    }

    public static bool IsAzureEventHubIdentifiableKey(string secret)
    {
        ulong[] checksumSeeds = new[]
        {
            AzureMessagingSendKeyChecksumSeed,
            AzureMessagingListenKeyChecksumSeed,
            AzureMessagingManageKeyChecksumSeed,
        };

        foreach (ulong checksumSeed in checksumSeeds)
        {
            try
            {
                if (IdentifiableSecrets.ValidateBase64Key(secret,
                                                          checksumSeed,
                                                          AzureEventHubSignature))
                {
                    return true;
                }
            }
            catch (FormatException) { return false; }
        }

        return false;
    }

    public static bool IsAzureFunctionIdentifiableKey(string secret)
    {
        ulong[] checksumSeeds = new[]
        {
            AzureFunctionKeyChecksumSeed,
            AzureFunctionSystemKeyChecksumSeed,
            AzureFunctionMasterKeyChecksumSeed,
        };

        foreach (ulong checksumSeed in checksumSeeds)
        {
            try
            {
                if (IdentifiableSecrets.ValidateBase64Key(secret,
                                                          checksumSeed,
                                                          AzureFunctionSignature,
                                                          encodeForUrl: true))
                {
                    return true;
                }
            }
            catch (FormatException) { return false; }
        }

        return false;
    }

    public static bool IsAzureIotHubIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureIotHubChecksumSeed,
                                                         AzureIotSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureIotDeviceProvisioningIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureIotDeviceProvisioningChecksumSeed,
                                                         AzureIotSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureIotDeviceIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureIotDeviceChecksumSeed,
                                                         AzureIotSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureApimIdentifiableDirectManagementKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureApimDirectManagementChecksumSeed,
                                                         AzureApimSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureApimIdentifiableSubscriptionKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureApimSubscriptionChecksumSeed,
                                                         AzureApimSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureApimIdentifiableGatewayKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureApimGatewayChecksumSeed,
                                                         AzureApimSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureApimIdentifiableRepositoryKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureApimRepositoryChecksumSeed,
                                                         AzureApimSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureMLWebServiceClassicIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureMLClassicChecksumSeed,
                                                         AzureMLClassicSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureRelayIdentifiableKey(string secret)
    {
        ulong[] checksumSeeds = new[]
        {
            AzureMessagingSendKeyChecksumSeed,
            AzureMessagingListenKeyChecksumSeed,
            AzureMessagingManageKeyChecksumSeed,
        };

        foreach (ulong checksumSeed in checksumSeeds)
        {
            try
            {
                if (IdentifiableSecrets.ValidateBase64Key(secret,
                                                           checksumSeed,
                                                           AzureRelaySignature))
                {
                    return true;
                }
            }
            catch (FormatException) { return false; }
        }

        return false;
    }

    public static bool IsAzureSearchIdentifiableAdminKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureSearchAdminKeyChecksumSeed,
                                                         AzureSearchSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureSearchIdentifiableQueryKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureSearchQueryKeyChecksumSeed,
                                                         AzureSearchSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsAzureServiceBusIdentifiableKey(string secret)
    {
        ulong[] checksumSeeds = new[]
        {
            AzureMessagingSendKeyChecksumSeed,
            AzureMessagingListenKeyChecksumSeed,
            AzureMessagingManageKeyChecksumSeed,
        };

        foreach (ulong checksumSeed in checksumSeeds)
        {
            try
            {
                if (IdentifiableSecrets.ValidateBase64Key(secret,
                                                          checksumSeed,
                                                          AzureServiceBusSignature))
                {
                    return true;
                }
            }
            catch (FormatException) { return false; }
        }

        return false;
    }

    public static bool IsAzureStorageAccountIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         AzureStorageAccountChecksumSeed,
                                                         AzureStorageSignature);
        }
        catch (FormatException) { return false; }
    }

    public static bool IsSqlIdentifiableKey(string secret)
    {
        try
        {
            return IdentifiableSecrets.ValidateBase64Key(secret,
                                                         SqlIdentifiableChecksumSeed,
                                                         SqlIdentifiableSignature);
        }
        catch (FormatException) { return false; }
        catch (ArgumentOutOfRangeException) { return false; }
    }

    private static bool AzureCacheForRedisWithSpecialCharacterChecksum(string secret, ulong checksumSeed)
    {
        byte[]? bytes = null;

        try
        {
            bytes = Convert.FromBase64String(secret);
        }
        catch (FormatException) { return false; }

#if !NET5_0_OR_GREATER
        int checksum = Marvin.ComputeHash32(bytes, checksumSeed, 0, bytes.Length);
#else
        int checksum = Marvin.ComputeHash32(new ReadOnlySpan<byte>(bytes), checksumSeed);
#endif
        byte[] checksumBytes = BitConverter.GetBytes(checksum);
        checksumBytes.CopyTo(bytes, bytes.Length - 4);

        string newSecret = Convert.ToBase64String(bytes);

#if NETCOREAPP3_1_OR_GREATER
        newSecret = newSecret.Replace("+", "P", StringComparison.Ordinal);
        newSecret = newSecret.Replace("/", "F", StringComparison.Ordinal);
#else
        newSecret = newSecret.Replace("+", "P");
        newSecret = newSecret.Replace("/", "F");
#endif
        return newSecret == secret;
    }
}
