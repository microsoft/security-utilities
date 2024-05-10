// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

#nullable enable
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

namespace Microsoft.Security.Utilities
{
    public abstract class Azure64ByteIdentifiableKey : IdentifiableKey
    {
        public string RegexNormalizedSignature => Signature.Replace("+", "\\+");

        public override uint KeyLength => 64;

        public override string Pattern
        {
            get => $@"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{76}}{RegexNormalizedSignature}[{WellKnownRegexPatterns.Base64}]{{5}}[AQgw]==){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }
    }
}