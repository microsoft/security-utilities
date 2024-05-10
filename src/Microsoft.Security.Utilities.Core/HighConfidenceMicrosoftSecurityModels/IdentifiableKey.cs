// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public abstract class IdentifiableKey : RegexPattern, IIdentifiableKey
    {
        private ISet<string>? _sniffLiterals;

        public IdentifiableKey()
        {
            RotationPeriod = TimeSpan.FromDays(365 * 2);
            DetectionMetadata = DetectionMetadata.Identifiable;
        }

        public abstract string Signature { get; }

        public virtual uint KeyLength => 32;

        public virtual bool EncodeForUrl => false;

        public abstract IEnumerable<ulong> ChecksumSeeds { get; }

        public override Tuple<string, string>? GetMatchIdAndName(string match)
        {
            foreach (ulong checksumSeed in ChecksumSeeds)
            {
                if (IdentifiableSecrets.ValidateBase64Key(match,
                                                          checksumSeed,
                                                          Signature))
                {
                    return new Tuple<string, string>(Id, Name);
                }
            }

            return null;
        }

        public override ISet<string>? SniffLiterals
        {
            get
            {
                _sniffLiterals ??= new HashSet<string>(new[] { Signature });
                return _sniffLiterals;
            }

            protected set => _sniffLiterals = value;
        }

        public override IEnumerable<string> GenerateTestExamples()
        {
            foreach (ulong checksumSeed in ChecksumSeeds)
            {
                string alphabet = EncodeForUrl ? WellKnownRegexPatterns.UrlSafeBase64 : WellKnownRegexPatterns.Base64;

                for (int i = 0; i < 5; i++)
                {
                    byte[] bytes = new byte[KeyLength];
                    int encodedLength = Convert.ToBase64String(bytes).Length;
                    string encoded = new string(alphabet[i], encodedLength);
                    Array.Copy(Convert.FromBase64String(encoded), bytes, KeyLength);

                    yield return
                        IdentifiableSecrets.GenerateBase64KeyHelper(checksumSeed,
                                                                    keyLengthInBytes: KeyLength,
                                                                    Signature,
                                                                    EncodeForUrl,
                                                                    bytes);
                }
            }
        }
    }
}
