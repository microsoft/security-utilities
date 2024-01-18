export class Marvin {
  public static ComputeHash(input: Uint8Array, seed: bigint): bigint {
    let p0: Uint32 = Uint32.from(Number(seed & 0xffffffffn));
    let p1: Uint32 = Uint32.from(Number((seed >> 32n) & 0xffffffffn));

    if (input.length >= 4) {
      const uData: Uint32Array = new Uint32Array(
        input.buffer.slice(0, input.length - (input.length % 4))
      );

      for (const data of uData) {
        p0 = p0.ADD(Uint32.from(data));
        [p0, p1] = Marvin.block(p0, p1);
      }

      input = input.slice(input.length - (input.length % 4));
    }

    switch (input.length) {
      case 0:
        p0 = p0.ADD(Uint32.from(0x80));
        break;
      case 1:
        p0 = p0.ADD(Uint32.from(0x8000).OR(Uint32.from(input[0])));
        break;
      case 2:
        let c1 = Uint32.from(input[0]);
        let c2 = Uint32.from(input[1]).SHIFTL(8);
        let c3 = Uint32.from(0x800000);
        p0 = p0.ADD(c1.OR(c2).OR(c3));
        break;
      case 3:
        let d0 = Uint32.from(0x80000000);
        let d1 = Uint32.from(input[0]);
        let d2 = Uint32.from(input[1]).SHIFTL(8);
        let d3 = Uint32.from(input[2]).SHIFTL(16);
        p0 = p0.ADD(d0.OR(d1).OR(d2).OR(d3));
        break;
      default:
        throw new Error("Invalid input length");
    }

    [p0, p1] = Marvin.block(p0, p1);
    [p0, p1] = Marvin.block(p0, p1);

    return (BigInt(p1.toRaw()) << 32n) | BigInt(p0.toRaw());
  }

  private static block(rp0: Uint32, rp1: Uint32): [Uint32, Uint32] {
    let p0: Uint32 = rp0;
    let p1: Uint32 = rp1;

    p1 = p1.XOR(p0);
    p0 = Marvin.rotate(p0, 20);

    p0 = p0.ADD(p1);
    p1 = Marvin.rotate(p1, 9);

    p1 = p1.XOR(p0);
    p0 = Marvin.rotate(p0, 27);

    p0 = p0.ADD(p1);
    p1 = Marvin.rotate(p1, 19);

    return [p0, p1];
  }

  private static rotate(value: Uint32, shift: number): Uint32 {
    return value.SHIFTL(shift).OR(value.SHIFTR(32 - shift));
  }
}

class Uint32 {
  constructor(private value: number) {}

  public static from(value: number): Uint32 {
    return new Uint32(value >>> 0);
  }

  public OR(b: Uint32): Uint32 {
    return Uint32.from((this.value | b.value) >>> 0);
  }

  public XOR(b: Uint32): Uint32 {
    return Uint32.from((this.value ^ b.value) >>> 0);
  }

  public ADD(b: Uint32): Uint32 {
    return Uint32.from((this.value + b.value) >>> 0);
  }

  public SHIFTL(shift: number): Uint32 {
    return Uint32.from((this.value << shift) >>> 0);
  }

  public SHIFTR(shift: number): Uint32 {
    return Uint32.from((this.value >>> shift) >>> 0);
  }

  public toRaw(): number {
    return this.value;
  }
}
