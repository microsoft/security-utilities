// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1600 // Elements should be documented

public interface ISecretMasker
{
    IEnumerable<Detection> DetectSecrets(string input);
    string MaskSecrets(string input);
}
