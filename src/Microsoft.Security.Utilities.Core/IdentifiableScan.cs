// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A class that scans data strictly for identifiable secrets.
/// </summary>
public class IdentifiableScan : ISecretMasker
{
    private bool generateCorrelatingIds;

    private readonly Dictionary<string, IList<RegexPattern>> signatureToPatternsMap;
    private readonly HighPerformanceScanner highPerformanceSecretScanner;
    private SecretMasker backupSecretMasker;
    private readonly IRegexEngine regexEngine;

    public IdentifiableScan(IEnumerable<RegexPattern> regexPatterns, bool generateCorrelatingIds, IRegexEngine regexEngine = null)
    {
        this.signatureToPatternsMap = new Dictionary<string, IList<RegexPattern>>();
        this.regexEngine = regexEngine ?? CachedDotNetRegex.Instance;
        this.generateCorrelatingIds = generateCorrelatingIds;

        var highPerformancePatterns = new HashSet<CompiledHighPerformancePattern>();

        foreach (RegexPattern pattern in regexPatterns)
        {
            if (pattern.Signatures == null)
            {
                PopulateBackupMasker(generateCorrelatingIds);
                this.backupSecretMasker.AddRegex(pattern);
                continue;
            }

            foreach (string signature in pattern.Signatures)
            {
                CompiledHighPerformancePattern highPerformancePattern = CompiledHighPerformancePattern.ForSignature(signature);
                if (highPerformancePattern == null)
                {
                    PopulateBackupMasker(generateCorrelatingIds);
                    this.backupSecretMasker.AddRegex(pattern);
                    continue;
                }

                if (!this.signatureToPatternsMap.TryGetValue(signature, out IList<RegexPattern> patterns))
                {
                    patterns = new List<RegexPattern>();
                    this.signatureToPatternsMap[signature] = patterns;
                }

                highPerformancePatterns.Add(highPerformancePattern);
                patterns.Add(pattern);
            }
        }

        this.highPerformanceSecretScanner = new HighPerformanceScanner(highPerformancePatterns);
    }

    private void PopulateBackupMasker(bool generateCorrelatingIds)
    {
        this.backupSecretMasker ??= new SecretMasker(regexSecrets: null,
                                                     generateCorrelatingIds,
                                                     this.regexEngine);
    }

    public IEnumerable<Detection> DetectSecrets(string input)
    {
        foreach (HighPerformanceDetection highPerformanceDetection in highPerformanceSecretScanner.Scan(input))
        {
            string found = input.Substring(highPerformanceDetection.Start, highPerformanceDetection.Length);
            foreach (RegexPattern pattern in this.signatureToPatternsMap[highPerformanceDetection.Signature])
            {
                Detection detection = FinalizeDetection(highPerformanceDetection, found, pattern);
                if (detection != null)
                {
                    yield return detection;
                    break;
                }
            }
        }

        if (backupSecretMasker != null)
        {
            foreach (Detection detection in backupSecretMasker.DetectSecrets(input))
            {
                yield return detection;
            }
        }
    }

    private Detection FinalizeDetection(HighPerformanceDetection detection, string found, RegexPattern pattern)
    {
        Tuple<string, string> result = pattern.GetMatchIdAndName(found);
        if (result == null)
        {
            return null;
        }

        string c3id = null;
        string preciseId = result.Item1;

        if (generateCorrelatingIds)
        {
            c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(found);
        }

        string redactionToken = c3id != null
            ? $"{preciseId}:{c3id}"
            : RegexPattern.FallbackRedactionToken;

        return new Detection(id: preciseId,
                             name: result.Item2,
                             label: pattern.Label,
                             start: detection.Start,
                             length: detection.Length,
                             redactionToken: redactionToken,
                             crossCompanyCorrelatingId: c3id,
                             metadata: pattern.DetectionMetadata,
                             rotationPeriod: pattern.RotationPeriod);
    }

    public void Dispose()
    {
    }

    string ISecretMasker.MaskSecrets(string input, Action<Detection> onDetection)
    {
        throw new NotImplementedException();
    }
}
