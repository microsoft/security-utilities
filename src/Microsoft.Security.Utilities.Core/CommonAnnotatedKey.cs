// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Base62;

#pragma warning disable RS0016 // Add public types and members to the declared API
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.Security.Utilities
{
    public class CommonAnnotatedKey
    {
        public static bool TryCreate(string key, out CommonAnnotatedKey secret)
        {
            secret = null;
            ulong checksumSeed = IdentifiableSecrets.VersionTwoChecksumSeed;
            string base64EncodedSignature = key.Substring(76, 4);
            bool isDerived = key[DerivedKeyCharacterOffset] == 'D';

            if (key.Length != IdentifiableSecrets.StandardCommonAnnotatedKeySize &&
                key.Length != IdentifiableSecrets.LongFormCommonAnnotatedKeySize)
            {
                return false;
            }

            bool longForm = key.Length == IdentifiableSecrets.LongFormCommonAnnotatedKeySize;

            // This code path is intended to ensure that common annotated security keys are
            // highly backwards compatible with the older identifiable keys format. This
            // should only entail providing the missing compute checksum byte of the key if
            // it is absent. The validation performed below is a fairly expensive operation.
            if (!longForm)
            {
                string partialEncodedChecksum = key.Substring(key.Length - 4);

                byte[] incomingKeyBytes = Convert.FromBase64String(key);
                byte[] keyBytes = new byte[64];
                Array.Copy(incomingKeyBytes, keyBytes, incomingKeyBytes.Length);

                int checksum = Marvin.ComputeHash32(keyBytes, checksumSeed, 0, keyBytes.Length - 4);

                byte[] checksumBytes = BitConverter.GetBytes(checksum);
                string encodedChecksum = isDerived ? checksum.ToBase62() : Convert.ToBase64String(checksumBytes);

                if (!encodedChecksum.StartsWith(partialEncodedChecksum))
                {
                    return false;
                }

                keyBytes[keyBytes.Length - 4] = checksumBytes[0];
                keyBytes[keyBytes.Length - 3] = checksumBytes[1];
                keyBytes[keyBytes.Length - 2] = checksumBytes[2];
                keyBytes[keyBytes.Length - 1] = checksumBytes[3];
                
                key = Convert.ToBase64String(keyBytes);
            }

            if (!IdentifiableSecrets.TryValidateBase64Key(key, checksumSeed, base64EncodedSignature))
            {
                return false;
            }

            byte[] bytes = Convert.FromBase64String(key);
            secret = new CommonAnnotatedKey(bytes);

            return true;
        }

        private byte[] bytes;
        private string base64Key;

        private CommonAnnotatedKey(byte[] bytes)
        {
            this.bytes = bytes;
            this.base64Key = Convert.ToBase64String(this.bytes);
        }

        /// <summary>
        /// The offset to the encoded standard fixed signature ('JQQJ99' or 'JQQJ9D').
        /// </summary>
        public const int StandardFixedSignatureOffset = 52;

        /// <summary>
        /// The encoded length of the standard fixed signature ('JQQJ99' or 'JQQJ9D').
        /// </summary>
        public const int StandardFixedSignatureLength = 6;

        /// <summary>
        /// The offset to the encoded character that denotes a derived ('D')
        /// or standard ('9') common annotated security key.
        /// </summary>
        public const int DerivedKeyCharacterOffset = StandardFixedSignatureOffset + StandardFixedSignatureLength - 1;

        /// <summary>
        /// The offset to the two-character encoded key creation date.
        /// </summary>
        public const int DateOffset = StandardFixedSignatureOffset + StandardFixedSignatureLength;

        /// <summary>
        /// The encoded length of the creation date (a value such as 'AE').
        /// </summary>
        public const int DateLength = 2;

        /// <summary>
        /// The offset to the 12-character encoded platform-reserved data.
        /// </summary>
        public const int PlatformReservedOffset = DateOffset + DateLength;

        /// <summary>
        /// The encoded length of the platform-reserved bytes.
        /// </summary>
        public const int PlatformReservedLength = 12;

        /// <summary>
        /// The offset to the 4-character encoded provider-reserved data.
        /// </summary>
        public const int ProviderReservedOffset = PlatformReservedOffset + PlatformReservedLength;

        /// <summary>
        /// The encoded length of the provider-reserved bytes.
        /// </summary>
        public const int ProviderReservedLength = 4;

        /// <summary>
        /// The offset to the 4-character encoded provider fixed signature.
        /// </summary>
        public const int ProviderFixedSignatureOffset = ProviderReservedOffset + ProviderReservedLength;

        /// <summary>
        /// The encoded length of the provider fixed signature, e.g., 'AZEG'.
        /// </summary>
        public const int ProviderFixedSignatureLength = 4;

        public const int ChecksumOffset = ProviderFixedSignatureOffset + ProviderFixedSignatureLength;

        public bool IsDerivedKey => this.base64Key[DerivedKeyCharacterOffset] == 'D';

        public bool IsLongFormKey => bytes.Length == 64;

        // 123456789012345678901234567890123456789012345678901234567890123456789012345678901234[5678]
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaJQQJ99ADccrrrrrtttttppppASIGixi1[xx==]

        public string StandardFixedSignature => this.base64Key.Substring(StandardFixedSignatureOffset, StandardFixedSignatureLength);

        public string DateText => this.base64Key.Substring(DateOffset, DateLength);

        public string PlatformReserved => this.base64Key.Substring(PlatformReservedOffset, PlatformReservedLength);

        public string ProviderReserved => this.base64Key.Substring(ProviderReservedOffset, ProviderReservedLength);

        public string ProviderFixedSignature => this.base64Key.Substring(ProviderFixedSignatureOffset, ProviderFixedSignatureLength);

        public DateTime CreationDate => ComputeDateTime(DateText);

        private static DateTime ComputeDateTime(string dateText)
        {
            if (dateText.Length != 2)
            {
                throw new ArgumentException("Invalid date text", nameof(dateText));
            }

            int year = 2024 + dateText[0] - 'A';
            int month = dateText[1] - 'A' + 1;

            return new DateTime(year, month, 1);
        }
    }
}
