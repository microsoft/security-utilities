// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

[Flags]
public enum DetectionKind
{
    // NOTE: The order here impacts which redaction token will be preferred when
    //       there are adjacent or overlapping redactions merged into a single
    //       token. Smaller values have priority over higher values so that
    //       literal redaction takes precedence over regex redaction.

    /// <summary>
    /// The detection was made using a literal value supplied to <see cref="SecretMasker.AddValue"/>.
    /// </summary>
    Literal = 0,

    /// <summary>
    /// The detection was made using a <see cref="RegexPattern"/>
    /// </summary>
    RegexPattern = 1,
}
