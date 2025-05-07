// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

/// <summary>
/// This class contains the version numbers of the library releases. Prior to
/// version 1.4.15, we did not properly maintain change tracking in our release
/// history and we have not back-filled release notes for all code changes. We
/// have added an explicit release version for every historical version where a
/// rule was introduced. And so we have release here for version 1.4.11 (because
/// SEC101/AadClientAppLegacyCredentials was added in this version) but we do
/// not have an entry for 1.4.14 (because no new rules were added in this
/// version).
/// </summary>
internal static class Releases
{
    // Current
    public static Version Unreleased => new Version(1, 18, 0);

    // Released versions
    public static Version Version_01_17_00 => new Version(1, 17, 0);
    public static Version Version_01_16_00 => new Version(1, 16, 0);
    public static Version Version_01_15_00 => new Version(1, 15, 0);
    public static Version Version_01_14_00 => new Version(1, 14, 0);
    public static Version Version_01_13_00 => new Version(1, 13, 0);
    public static Version Version_01_12_00 => new Version(1, 12, 0);
    public static Version Version_01_11_00 => new Version(1, 11, 0);
    public static Version Version_01_10_00 => new Version(1, 10, 0);
    public static Version Version_01_09_01 => new Version(1, 9, 1);
    public static Version Version_01_08_00 => new Version(1, 8, 0);
    public static Version Version_01_07_00 => new Version(1, 7, 0);
    public static Version Version_01_06_00 => new Version(1, 6, 0);
    public static Version Version_01_05_02 => new Version(1, 5, 2);
    public static Version Version_01_05_01 => new Version(1, 5, 1);
    public static Version Version_01_05_00 => new Version(1, 5, 0);
    public static Version Version_01_04_25 => new Version(1, 4, 25);
    public static Version Version_01_04_24 => new Version(1, 4, 24);
    public static Version Version_01_04_22 => new Version(1, 4, 22);
    public static Version Version_01_04_21 => new Version(1, 4, 21);
    public static Version Version_01_04_20 => new Version(1, 4, 20);
    public static Version Version_01_04_19 => new Version(1, 4, 19);
    public static Version Version_01_04_18 => new Version(1, 4, 18);
    public static Version Version_01_04_17 => new Version(1, 4, 17);
    public static Version Version_01_04_16 => new Version(1, 4, 16);
    public static Version Version_01_04_15 => new Version(1, 4, 15);
    public static Version Version_01_04_12 => new Version(1, 4, 12);
    public static Version Version_01_04_10 => new Version(1, 4, 10);
    public static Version Version_01_04_02 => new Version(1, 4, 2);
}