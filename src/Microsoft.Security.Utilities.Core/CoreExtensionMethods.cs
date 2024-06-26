﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal static class CoreExtensionMethods
    {
        public static ISet<string> ToSet(this string value)
        {
            return new HashSet<string> { value };
        }
        public static ISet<string> ToSet(this IEnumerable<string> value)
        {
            return new HashSet<string>(value);
        }
    }
}
