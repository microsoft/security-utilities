// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable IDE0073 // A source file contains a header that does not match the required text.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Microsoft.Security.Utilities;

[Flags]
internal enum DetectionMetadata
{
    None = 0,

    ObsoleteFormat = 1 << 0,

    HighEntropy = 1 << 1,

    FixedSignature = 1 << 2,

    EmbeddedChecksum = 1 << 3,

    ClearSurroundingContext = 1 << 4,

    HighConfidence = FixedSignature | EmbeddedChecksum | ClearSurroundingContext,

    Identifiable = FixedSignature | EmbeddedChecksum | HighEntropy,

    RequiresRotation = 1 << 5,
}
