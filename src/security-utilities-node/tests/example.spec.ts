import { test, expect } from '@playwright/test';
import { Marvin } from '../marvin';

test('basic test', async () => {
  const seed = BigInt("0xd53cd9cecd0893b7");
  const text = "abc";
  const input = new TextEncoder().encode(text);

  const expected = "0x22c74339492769bf";
  const marvin = Marvin.ComputeHash(input, seed);

  expect(`0x${marvin.toString(16)}`).toBe(expected);
});

test('Longer String', async () => {
  const seed = BigInt("0xddddeeeeffff000");
  const text = "abcdefghijklmnopqrstuvwxyz";
  const input = new TextEncoder().encode(text);

  const expected = "0xa128eb7e7260aca2";
  const marvin = Marvin.ComputeHash(input, seed);

  expect(`0x${marvin.toString(16)}`).toBe(expected);
});

test('Longer String 2', async () => {
  const seed = BigInt("0x804fb61a801bdbcc");
  const text = "\x09\x32\xe6\x24\x6c\x47";
  const input = Uint8Array.from([255, 0, 255, 0, 255, 0, 255]); 
  const expected = "0xfdfd187b1d3ce784";
  const marvin = Marvin.ComputeHash(input, seed);

  expect(`0x${marvin.toString(16)}`).toBe(expected);
})