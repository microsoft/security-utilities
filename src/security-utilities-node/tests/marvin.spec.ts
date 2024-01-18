import { test, expect } from "@playwright/test";
import { Marvin } from "../marvin";

interface TestCase {
  title?: string;
  seed: string;
  data: Uint8Array;
  checksum64: string;
  checksum32: string;
}

const seed0: string = "0x004fb61a001bdbcc";
const seed1: string = "0x804fb61a001bdbcc";
const seed2: string = "0x804fb61a801bdbcc";

const cases: TestCase[] = [
  {
    title: "basic",
    seed: "0xd53cd9cecd0893b7",
    data: new TextEncoder().encode("abc"),
    checksum64: "0x22c74339492769bf",
    checksum32: "0x6be02a86",
  },
  {
    title: "longer",
    seed: "0xddddeeeeffff000",
    data: new TextEncoder().encode("abcdefghijklmnopqrstuvwxyz"),
    checksum64: "0xa128eb7e7260aca2",
    checksum32: "0xd34847dc",
  },

  // seed0 cases
  {
    seed: seed0,
    data: new TextEncoder().encode(""),
    checksum64: "0x30ed35c100cd3c7d",
    checksum32: "0x302009bc",
  },
  {
    seed: seed0,
    data: new Uint8Array([175]),
    checksum64: "0x48e73fc77d75ddc1",
    checksum32: "0x3592e206",
  },
  {
    seed: seed0,
    data: new Uint8Array([231, 15]),
    checksum64: "0xb5f6e1fc485dbff8",
    checksum32: "0xfdab5e04",
  },
  {
    seed: seed0,
    data: new Uint8Array([55, 244, 149]),
    checksum64: "0xf0b07c789b8cf7e8",
    checksum32: "0x6b3c8b90",
  },
  {
    seed: seed0,
    data: new Uint8Array([134, 66, 220, 89]),
    checksum64: "0x7008f2e87e9cf556",
    checksum32: "0x0e9407be",
  },
  {
    seed: seed0,
    data: new Uint8Array([21, 63, 183, 152, 38]),
    checksum64: "0xe6c08c6da2afa997",
    checksum32: "0x446f25fa",
  },
  {
    seed: seed0,
    data: new Uint8Array([9, 50, 230, 36, 108, 71]),
    checksum64: "0x6f04bf1a5ea24060",
    checksum32: "0x31a6ff7a",
  },
  {
    seed: seed0,
    data: new Uint8Array([171, 66, 126, 168, 209, 15, 199]),
    checksum64: "0xe11847e4f0678c41",
    checksum32: "0x117fcba5",
  },

  // seed1 testcases
  {
    seed: seed1,
    data: new TextEncoder().encode(""),
    checksum64: "0x10a9d5d3996fd65d",
    checksum32: "0x89c6038e",
  },
  {
    seed: seed1,
    data: new Uint8Array([175]),
    checksum64: "0x68201f91960ebf91",
    checksum32: "0xfe2ea000",
  },
  {
    seed: seed1,
    data: new Uint8Array([231, 15]),
    checksum64: "0x64b581631f6ab378",
    checksum32: "0x7bdf321b",
  },
  {
    seed: seed1,
    data: new Uint8Array([55, 244, 149]),
    checksum64: "0xe1f2dfa6e5131408",
    checksum32: "0x04e1cbae",
  },
  {
    seed: seed1,
    data: new Uint8Array([134, 66, 220, 89]),
    checksum64: "0x36289d9654fb49f6",
    checksum32: "0x62d3d460",
  },
  {
    seed: seed1,
    data: new Uint8Array([21, 63, 183, 152, 38]),
    checksum64: "0x0a06114b13464dbd",
    checksum32: "0x19405cf6",
  },
  {
    seed: seed1,
    data: new Uint8Array([9, 50, 230, 36, 108, 71]),
    checksum64: "0xd6dd5e40ad1bc2ed",
    checksum32: "0x7bc69cad",
  },
  {
    seed: seed1,
    data: new Uint8Array([171, 66, 126, 168, 209, 15, 199]),
    checksum64: "0xe203987dba252fb3",
    checksum32: "0x5826b7ce",
  },

  // seed2 testcases
  {
    seed: seed2,
    data: new Uint8Array([0]),
    checksum64: "0xa37fb0da2ecae06c",
    checksum32: "0x8db550b6",
  },
  {
    seed: seed2,
    data: new Uint8Array([255]),
    checksum64: "0xfecef370701ae054",
    checksum32: "0x8ed41324",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255]),
    checksum64: "0xa638e75700048880",
    checksum32: "0xa63c6fd7",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0]),
    checksum64: "0xbdfb46d969730e2a",
    checksum32: "0xd48848f3",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255]),
    checksum64: "0x9d8577c0fe0d30bf",
    checksum32: "0x6388477f",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0]),
    checksum64: "0x4f9fbdde15099497",
    checksum32: "0x5a962949",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255]),
    checksum64: "0x24eaa279d9a529ca",
    checksum32: "0xfd4f8bb3",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0]),
    checksum64: "0xd3bec7726b057943",
    checksum32: "0xb8bbbe31",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255]),
    checksum64: "0x920b62bbca3e0b72",
    checksum32: "0x583569c9",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0]),
    checksum64: "0x1d7ddf9dfdf3c1bf",
    checksum32: "0xe08e1e22",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0, 255]),
    checksum64: "0xec21276a17e821a5",
    checksum32: "0xfbc906cf",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255, 0]),
    checksum64: "0x6911a53ca8c12254",
    checksum32: "0xc1d08768",
  },
  {
    seed: seed2,
    data: new Uint8Array([255, 0, 255, 0, 255, 0, 255]),
    checksum64: "0xfdfd187b1d3ce784",
    checksum32: "0xe0c1ffff",
  },
  {
    seed: seed2,
    data: new Uint8Array([0, 255, 0, 255, 0, 255, 0]),
    checksum64: "0x71876f2efb1b0ee8",
    checksum32: "0x8a9c61c6",
  },
];

for (const testCase of cases)
  test(
    testCase.title ?? `MarvinHash(${testCase.seed}, ${testCase.data})`,
    async () => {
      const hash64 = Marvin.ComputeHash(testCase.data, BigInt(testCase.seed));
      expect(`0x${hash64.toString(16).padStart(16, "0")}`).toBe(
        testCase.checksum64
      );

      const hash32 = Marvin.ComputeHash32(testCase.data, BigInt(testCase.seed));
      expect(`0x${hash32.toString(16).padStart(8, "0")}`).toBe(
        testCase.checksum32
      );
    }
  );
