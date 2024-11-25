import { scrypt } from "ethereum-cryptography/scrypt";

const HexCharacters = "0123456789abcdef";

export const randomBytes = (size: number) => {
  return globalThis.crypto.getRandomValues(new Uint8Array(size));
};

export const hexlify = (bytes: Uint8Array) => {
  let result = "0x";

  for (let i = 0; i < bytes.length; i++) {
    const v = bytes[i]!;
    result += HexCharacters[(v & 0xf0) >> 4]! + HexCharacters[v & 0x0f]!;
  }

  return result;
};

export const getBytes = (value: string): Uint8Array => {
  if (typeof value === "string" && /^0x(?:[0-9a-f][0-9a-f])*$/i.exec(value)) {
    const result = new Uint8Array((value.length - 2) / 2);
    let offset = 2;

    for (let i = 0; i < result.length; i++) {
      result[i] = parseInt(value.substring(offset, offset + 2), 16);
      offset += 2;
    }

    return result;
  }

  throw new Error("invalid hex string");
};

export { scrypt };
