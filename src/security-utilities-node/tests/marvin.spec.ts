import { test, expect } from "@playwright/test";
import { Marvin } from "../marvin";

interface TestCase {
  title?: string;
  seed: string;
  data: Uint8Array;
  checksum: string;
}

const seed0: string = "0x004fb61a001bdbcc";
const seed1: string = "0x804fb61a001bdbcc";
const seed2: string = "0x804fb61a801bdbcc";

const cases: TestCase[] = [
  { title: 'basic', seed: "0xd53cd9cecd0893b7", data: new TextEncoder().encode("abc"), checksum: "0x22c74339492769bf" },
  { title: 'longer', seed: "0xddddeeeeffff000", data: new TextEncoder().encode("abcdefghijklmnopqrstuvwxyz"), checksum: "0xa128eb7e7260aca2" },

  { seed: seed0, data: new TextEncoder().encode(""), checksum: "0x30ed35c100cd3c7d" },
  { seed: seed0, data: new Uint8Array([175]), checksum: "0x48e73fc77d75ddc1" },
  {
    seed: seed0,
    data: new Uint8Array([231, 15]),
    checksum: "0xb5f6e1fc485dbff8",
  },
  {
    seed: seed0,
    data: new Uint8Array([55, 244, 149]),
    checksum: "0xf0b07c789b8cf7e8",
  },
  {
    seed: seed0,
    data: new Uint8Array([134, 66, 220, 89]),
    checksum: "0x7008f2e87e9cf556",
  },
  {
    seed: seed0,
    data: new Uint8Array([21, 63, 183, 152, 38]),
    checksum: "0xe6c08c6da2afa997",
  },
  {
    seed: seed0,
    data: new Uint8Array([9, 50, 230, 36, 108, 71]),
    checksum: "0x6f04bf1a5ea24060",
  },
  {
    seed: seed0,
    data: new Uint8Array([171, 66, 126, 168, 209, 15, 199]),
    checksum: "0xe11847e4f0678c41",
  },

  // seed_1 testcases
  { seed: seed1, data: new TextEncoder().encode(""), checksum: "0x10a9d5d3996fd65d" },
  { seed: seed1, data: new Uint8Array([175]), checksum: "0x68201f91960ebf91" },
  {
    seed: seed1,
    data: new Uint8Array([231, 15]),
    checksum: "0x64b581631f6ab378",
  },
  {
    seed: seed1,
    data: new Uint8Array([55, 244, 149]),
    checksum: "0xe1f2dfa6e5131408",
  },
  {
    seed: seed1,
    data: new Uint8Array([134, 66, 220, 89]),
    checksum: "0x36289d9654fb49f6",
  },
  {
    seed: seed1,
    data: new Uint8Array([21, 63, 183, 152, 38]),
    checksum: "0x0a06114b13464dbd",
  },
  {
    seed: seed1,
    data: new Uint8Array([9, 50, 230, 36, 108, 71]),
    checksum: "0xd6dd5e40ad1bc2ed",
  },
  {
    seed: seed1,
    data: new Uint8Array([171, 66, 126, 168, 209, 15, 199]),
    checksum: "0xe203987dba252fb3",
  },

  // seed_2 testcases
  { seed: seed2, data: new Uint8Array([0]), checksum: "0xa37fb0da2ecae06c" },
  { seed: seed2, data: new Uint8Array([255]), checksum: "0xfecef370701ae054" },
  { seed: seed2, data: new Uint8Array([0, 255]), checksum: "0xa638e75700048880" },
  { seed: seed2, data: new Uint8Array([255, 0]), checksum: "0xbdfb46d969730e2a" },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255]),
    checksum: "0x9d8577c0fe0d30bf",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0]),
    checksum: "0x4f9fbdde15099497",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255]),
    checksum: "0x24eaa279d9a529ca",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0]),
    checksum: "0xd3bec7726b057943",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255]),
    checksum: "0x920b62bbca3e0b72",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0]),
    checksum: "0x1d7ddf9dfdf3c1bf",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0, 255]),
    checksum: "0xec21276a17e821a5",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255, 0]),
    checksum: "0x6911a53ca8c12254",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255, 0, 255]),
    checksum: "0xfdfd187b1d3ce784",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0, 255, 0]),
    checksum: "0x71876f2efb1b0ee8",
  },
];

for (const testCase of cases)
  test(testCase.title ?? `MarvinHash(${testCase.seed}, ${testCase.data})`, async () => {
    const marvin = Marvin.ComputeHash(testCase.data, BigInt(testCase.seed));
    expect(`0x${marvin.toString(16).padStart(16, '0')}`).toBe(testCase.checksum);
  });
