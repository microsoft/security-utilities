// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1600 // Elements should be documented

internal interface ISecretMasker
{
    ICollection<Detection> DetectSecrets(string input);
    string MaskSecrets(String input);
}
