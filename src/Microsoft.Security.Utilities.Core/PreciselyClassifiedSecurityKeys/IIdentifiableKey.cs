﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public interface IIdentifiableKey
    {
        public string Id { get; }

        public string Name { get; } 
        
        public uint KeyLength { get; }
        
        public bool EncodeForUrl { get; }

        public ISet<string> Signatures { get; }

        public IEnumerable<ulong> ChecksumSeeds { get; }
    }
}