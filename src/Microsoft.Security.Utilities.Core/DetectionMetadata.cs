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

    // The confidence that this pattern comprises sensitive data is effectively 100%.
    // The 'identifiable' techniques for constructing security keys provides accuracy 
    // that guarantees false positives at a rate that exceeds 1 in billions.
    Identifiable = FixedSignature | EmbeddedChecksum | HighEntropy | HighConfidence,

    RequiresRotation = 1 << 4,

    Unclassified = 1 << 5,

    /// <summary>
    /// The confidence that this pattern comprises sensitive data is low. i.e., the chance
    /// that this pattern matches some other data generator and does not comprises anything
    /// related to a security scenario is high. A 32-byte base64-encoded string, for example,
    /// may comprise an Azure access key in some scenarios but in the vast majority of matches
    /// it will simply be some other encoded data that happens to be 32 bytes long.
    /// Configuring an analysis to include `LowConfidence` patterns is appropriate for data
    /// collection scenarios where the goal is to maximize the number of matches or for
    /// extremely detailed reviews of findings in urgent security scenarios that warrant it.
    /// </summary>
    LowConfidence = 1 << 6,

    /// <summary>
    /// The confidence that this pattern comprises sensitive data is medium. i.e., in most
    /// scenarios, we expect this finding first to identify data that is directed to a
    /// specific security purpose. The pattern may *not* be sufficiently accurate to
    /// determine whether the data actually comprises an exploitable credential (i.e., it
    /// includes the literally sensitive data required to satisfy auth flows). Instead, the
    /// match may be a false positive, in that the apparent secret actually comprises an
    /// expanded variable. Configuring an analysis to include `MediumConfidence` patterns is
    /// appropriate in scenarios where the productivity costs of reviewing and ignoreing
    /// false positives is offset by the security value achieved. A scan system that
    /// identifies medium confidence findings in incremental code changes, for example, can
    /// typically amortize the productivity costs of medium confidence findings. A system
    /// that attempts to hard-block processes based on detecting an apparent credential
    /// would not enable medium confidence patterns.
    /// </summary>
    MediumConfidence = 1 << 7,

    // The confidence that this pattern comprises sensitive data is very high. i.e., the
    // productivity costs associated with reviewing and ignoring false positives is extremely
    // low or non-existent. Note that a pattern that is marked as `DetectionMetadata.Identifiable`
    // has accuracy that is effectively 100%. 
    HighConfidence = 1 << 8,
}
