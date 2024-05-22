// Copyright (c) Microsoft. All rights reserved.
using Base62;

using System;

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

            if (key.Length != 88 && key.Length != 84)
            {
                return false;
            }

            if (key.Length == 84)
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

        public byte[] KeyBytes { get; protected set; }

        public string EncodedKey { get; protected set; }

        protected CommonAnnotatedKey() { }

        private CommonAnnotatedKey(byte[] bytes)
        {
            this.KeyBytes = bytes;
            this.EncodedKey = Convert.ToBase64String(this.KeyBytes);
        }

        public const int DerivedKeyCharacterOffset = 57;

        public bool IsDerivedKey => this.EncodedKey[DerivedKeyCharacterOffset] == 'D';

        public bool IsLongFormKey => this.KeyBytes.Length == 64;

        // 123456789012345678901234567890123456789012345678901234567890123456789012345678901234[5678]
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaJQQJ99ADccrrrrrtttttppppASIGixi1[xx==]

        public string StandardFixedSignature => this.EncodedKey.Substring(52, 6);

        public string DateText => this.EncodedKey.Substring(58, 2);

        public string PlatformReserved => this.EncodedKey.Substring(60, 12);

        public string ProviderReserved => this.EncodedKey.Substring(72, 4);

        public string ProviderFixedSignature => this.EncodedKey.Substring(76, 4);

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
