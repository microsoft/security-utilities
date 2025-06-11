// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/177";
        Name = nameof(SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_177_SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.SqlServerPrivate;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
