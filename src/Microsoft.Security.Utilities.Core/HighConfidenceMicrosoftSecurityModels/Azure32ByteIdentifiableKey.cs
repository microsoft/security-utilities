// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

#nullable enable
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

namespace Microsoft.Security.Utilities
{
    public abstract class Azure32ByteIdentifiableKey : RegexPattern, IIdentifiableKey
    {
        private ISet<string>? _sniffLiterals;

        public Azure32ByteIdentifiableKey()
        {
            RotationPeriod = TimeSpan.FromDays(365 * 2);
            DetectionMetadata = DetectionMetadata.Identifiable;
        }

        public abstract string Signature { get; }

        public uint KeyLength => 32;

        public abstract IEnumerable<ulong> ChecksumSeeds { get; }

        public string RegexNormalizedSignature => Signature.Replace("+", "\\+");

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{33}}{RegexNormalizedSignature}[A-P][{WellKnownRegexPatterns.Base64}]{{5}}=){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
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

        public override IEnumerable<string> GenerateTestExamples()
        {
            foreach (ulong checksumSeed in ChecksumSeeds)
            {
                yield return
                    IdentifiableSecrets.GenerateStandardBase64Key(checksumSeed,
                                                                  keyLengthInBytes: KeyLength,
                                                                  Signature);
            }
        }

        private const string TerminalCharactersFor64ByteKey = "AQgw";
    }
}