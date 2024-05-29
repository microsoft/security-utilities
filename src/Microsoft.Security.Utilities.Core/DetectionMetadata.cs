// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

[Flags]
public enum DetectionMetadata
{
    None = 0,

    ObsoleteFormat = 1 << 0,

    HighEntropy = 1 << 1,

    FixedSignature = 1 << 2,

    EmbeddedChecksum = 1 << 3,

    ClearSurroundingContext = 1 << 4,

    Identifiable = FixedSignature | EmbeddedChecksum | HighEntropy,

    RequiresRotation = 1 << 5,
}
