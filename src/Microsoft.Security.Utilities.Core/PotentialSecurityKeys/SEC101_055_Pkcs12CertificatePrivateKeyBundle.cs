// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace Microsoft.Security.Utilities
{
    public class Pkcs12CertificatePrivateKeyBundle : RegexPattern
    {
        public Pkcs12CertificatePrivateKeyBundle()
        {
            Id = "SEC101/055";
            Name = nameof(Pkcs12CertificatePrivateKeyBundle);
            Pattern = @"MI[I-L][0-9a-zA-Z\/+]{2}[AQgw]IBAzCC";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
#if NET6_0_OR_GREATER
            foreach (string? password in new string?[] { Guid.NewGuid().ToString(), null })
            {
                foreach (int keyLength in new int[] { 1024, 2048, 4096 })
                {
                    yield return GenerateTestPkcs12(keyLength, password);
                }
            }

            // Example showing regex will matchh in the middle of the string (i.e. unanchored).
            yield return $"some padding data {GenerateTestPkcs12(2048, null)} more padding data";

            // Example showing incomplete data will match.
            yield return GenerateTestPkcs12(2048, null).Substring(0, 20);
#else
            return [];
#endif
        }

#if NET6_0_OR_GREATER
        private static string GenerateTestPkcs12(int keyLength, string? password)
        {
            using var rsa = RSA.Create(keyLength);
            var certRequest = new CertificateRequest("cn=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
            var pkcs12 = cert.Export(X509ContentType.Pkcs12, password);
            return Convert.ToBase64String(pkcs12);
        }
#else
        private static string GenerateTestPkcs12(int keyLength, string? password)
        {
            throw new NotImplementedException("'GenerateTestPkcs12' is not yet implemented for TargetFrameworks lower than net451.");
        }
#endif

    }
}
