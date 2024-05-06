
using BenchmarkDotNet.Running;

using Benchmarks;

var summary = BenchmarkRunner.Run<RegexEngineDetectionBenchmarks>();