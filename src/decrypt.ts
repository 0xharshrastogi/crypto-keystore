import { keccak256 } from "ethereum-cryptography/keccak";
import { getBytes, hexlify, scrypt } from "./crypto-utils.js";
import type { Keystore } from "./encrypt.js";
import { encodeText } from "./utils.js";

export const decrypt = async (
  keystore: Keystore,
  password: string
): Promise<Uint8Array> => {
  if (keystore.cipher !== "aes-128-ctr") {
    throw new Error(`Unsupported cipher ${keystore.cipher}`);
  }

  if (keystore.kdf !== "scrypt") {
    throw new Error(`Unsupported kdf ${keystore.kdf}`);
  }

  const iv = getBytes(keystore.cipherparams.IV);
  const derivedKey = await scrypt(
    encodeText(password),
    getBytes(keystore.kdfparams.salt),
    keystore.kdfparams.n,
    keystore.kdfparams.r,
    keystore.kdfparams.p,
    keystore.kdfparams.dklen
  );

  const encryptKey = derivedKey.slice(0, 16);
  const cipherText = getBytes(keystore.cipherText);
  const hash = keccak256(
    Uint8Array.from([...derivedKey.slice(16, 32), ...cipherText])
  );

  if (hexlify(hash) !== keystore.mac) {
    throw new Error("Invalid password");
  }

  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    encryptKey,
    { name: "AES-CTR" },
    true,
    ["decrypt"]
  );

  const data = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-CTR",
      counter: iv,
      length: 64,
    },
    key,
    cipherText
  );
  return new Uint8Array(data);
};
