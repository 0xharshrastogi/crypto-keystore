import { keccak256 } from "ethereum-cryptography/keccak";
import { hexlify, randomBytes, scrypt } from "./crypto-utils.js";
import { encodeText } from "./utils.js";

export type Keystore = {
  cipher: string;
  cipherText: string;
  cipherparams: {
    IV: string;
  };
  kdf: string;
  kdfparams: {
    n: number;
    r: number;
    p: number;
    dklen: number;
    salt: string;
  };
  mac: string;
};

export type Algorithm = "aes-128-ctr";

/**
 * Encrypts the given data using the specified algorithm and password.
 *
 * @param data - The data to be encrypted as a Uint8Array.
 * @param algorithm - The encryption algorithm to use. Currently, only "aes-128-ctr" is supported.
 * @param password - The password to derive the encryption key from.
 * @returns A promise that resolves to a Keystore object containing the encrypted data and encryption parameters.
 *
 * @throws Will throw an error if the specified algorithm is not supported.
 */
export const encrypt = async (
  data: Uint8Array,
  algorithm: Algorithm,
  password: string
): Promise<Keystore> => {
  if (algorithm !== "aes-128-ctr") {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const N = 2 << 11;
  const r = 8;
  const p = 1;
  const dklen = 32;

  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derivedKey = await scrypt(encodeText(password), salt, N, r, p, dklen);
  const encryptKey = derivedKey.slice(0, 16);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encryptKey,
    { name: "AES-CTR" },
    true,
    ["encrypt"]
  );

  const cipherText = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-CTR",
      counter: iv,
      length: 64,
    },
    key,
    data
  );

  const macData = Uint8Array.from([
    ...derivedKey.slice(16, 32),
    ...new Uint8Array(cipherText),
  ]);
  const mac = keccak256(macData);

  return {
    cipher: "aes-128-ctr",
    cipherText: hexlify(new Uint8Array(cipherText)),
    cipherparams: { IV: hexlify(iv) },
    kdf: "scrypt",
    kdfparams: { n: N, r, p, dklen, salt: hexlify(salt) },
    mac: hexlify(mac),
  };
};
