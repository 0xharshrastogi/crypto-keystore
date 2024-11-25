import assert from "node:assert";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { decrypt, encrypt } from "../index.js";

describe("decrypt", async () => {
  const message = randomBytes(32).toString("hex");
  const password = "password";

  const keystore = await encrypt(
    new TextEncoder().encode(message),
    "aes-128-ctr",
    password
  );

  it("should decrypt a message", async () => {
    const decrypted = await decrypt(keystore, password);

    assert(
      new TextDecoder().decode(decrypted) === message,
      "decrypted message does not match"
    );
  });

  it("should throw an error if the password is incorrect", async () => {
    const incorrectPassword = "incorrect password";

    try {
      await decrypt(keystore, incorrectPassword);
      assert.fail("Expected an error to be thrown for an incorrect password.");
    } catch (error) {
      assert(
        error instanceof Error,
        "Expected an error to be thrown for an incorrect password."
      );
    }
  });
});
