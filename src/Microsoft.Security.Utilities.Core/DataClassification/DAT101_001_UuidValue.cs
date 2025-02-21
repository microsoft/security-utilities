// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class UuidValue : RegexPattern
    {
        internal const string c_Nil = "00000000-0000-0000-0000-000000000000";
        internal const string c_Max = "ffffffff-ffff-ffff-ffff-ffffffffffff";

        public UuidValue()
        {
            Id = "DAT101/001";
            Name = nameof(UuidValue);
            Pattern = @"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}" + 
                      $"|{c_Nil}|{c_Max}$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // Example of nil UUID.
            yield return "00000000-0000-0000-0000-000000000000";

            // Example of max UUID.
            yield return "ffffffff-ffff-ffff-ffff-ffffffffffff";

            // Example of a UUIDv1 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv1-value.
            yield return "C232AB00-9414-11EC-B3C8-9F6BDECED846";

            // Example of UUIDv2 Value. NB: v2 is rarely seen in the wild as the spec was deprecated and most libraries do not even implement it.
            yield return "000004d2-92e8-21ed-8100-3fdb0085247e";

            // Example of a UUIDv3 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv3-value.
            yield return "5df41881-3aed-3515-88a7-2f4a814cf09e";

            // Example of a UUIDv4 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv4-value.
            yield return "919108f7-52d1-4320-9bac-f847db4148a8";

            // Example of a UUIDv5 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv5-value.
            yield return "2ed6657d-e927-568b-95e1-2665a8aea6a2";

            // Example of a UUIDv6 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv6-value.
            yield return "1EC9414C-232A-6B00-B3C8-9F6BDECED846";

            // Example of a UUIDv7 Value from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv7-value.
            yield return "017F22E2-79B0-7CC3-98C4-DC0C0C07398F";

            // Example of a UUIDv8 Value (Time-Based) from https://www.rfc-editor.org/rfc/rfc9562.html#name-example-of-a-uuidv8-value-t.
            yield return "2489E9AD-2EE2-8E00-8EC9-32D5F69181C0";
        }
    }
}
