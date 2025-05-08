// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

#if NET6_0_OR_GREATER
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#endif

#nullable enable

namespace Microsoft.Security.Utilities
{
    public class Pkcs12CertificatePrivateKeyBundle : RegexPattern
    {
        public Pkcs12CertificatePrivateKeyBundle()
        {
            Id = "SEC101/055";
            Name = nameof(Pkcs12CertificatePrivateKeyBundle);
            Label = "a PKCS#12 certificate private key bundle";
            DetectionMetadata = DetectionMetadata.MediumConfidence;
            Pattern = @"MI[I-L][0-9a-zA-Z\/+]{2}[AQgw]IBAzCC";
            Signatures = new HashSet<string>(["IBAzCC"]);
        }

        public override Version CreatedVersion => Releases.Version_01_14_00;

        public override Version LastUpdatedVersion => Releases.Version_01_14_00;

        // _truePositiveExamples is used during testing, including a stress test where this code absent caching
        // is would case the stress test (n=1000) to take 10+ minutes to run due the expensive nature of generating
        // private keys and certificates. We use Lazy here since during non-test execution we do not want to incur
        // the cost of generating these examples.
        private static Lazy<List<string>> _truePositiveExamples = new Lazy<List<string>>(() =>
        {
            var examples = new List<string>();
#if NET6_0_OR_GREATER
            foreach (string? password in new string?[] { Guid.NewGuid().ToString(), null })
            {
                foreach (int keyLength in new int[] { 1024, 2048, 4096 })
                {
                    examples.Add(GenerateTestPkcs12(keyLength, password));
                }
            }

            // Example showing regex will matchh in the middle of the string (i.e. unanchored).
            examples.Add($"some padding data {GenerateTestPkcs12(2048, null)} more padding data");

            // Example showing incomplete data will match.
            examples.Add(GenerateTestPkcs12(2048, null).Substring(0, 20));
#endif
            return examples;
        });

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            return _truePositiveExamples.Value;
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
