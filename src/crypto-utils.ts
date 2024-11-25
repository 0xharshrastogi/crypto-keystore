import { randomBytes, scrypt as scryptNode } from "node:crypto";

export const scrypt = async (
  password: Uint8Array,
  salt: Uint8Array,
  n: number,
  p: number,
  r: number,
  dkLen: number
) => {
  const promise = new Promise<Uint8Array>((resolve, reject) => {
    scryptNode(password, salt, dkLen, { N: n, r, p }, (err, key) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(key);
    });
  });

  return promise;
};

export const hexlify = (bytes: Uint8Array) => {
  return Buffer.from(bytes).toString("hex");
};

export const getBytes = (hex: string) => {
  return new Uint8Array(
    Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex")
  );
};

export { randomBytes };
