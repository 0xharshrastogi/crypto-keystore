import assert, { fail } from "node:assert";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { encrypt } from "../index.js";

describe("encrypt", () => {
  it("should encrypt a message", async () => {
    const message = "Hello, World!";
    const password = "password";

    const keystore = await encrypt(
      new TextEncoder().encode(message),
      "aes-128-ctr",
      password
    );

    assert(typeof keystore === "object", "keystore is not an object");
    assert(keystore.cipher === "aes-128-ctr", "cipher is not aes-128-ctr");
  });

  it("should throw an error for an unsupported cipher", async (t) => {
    const message = "Hello, World!";
    const password = "password";
    const algorithm = randomBytes(16).toString("hex");
    try {
      // @ts-ignore
      await encrypt(new TextEncoder().encode(message), algorithm, password);
      fail("Expected an error to be thrown for an unsupported cipher.");
    } catch (error) {
      const message = error instanceof Error ? error.message : error;

      assert(typeof error === "object", "unexpected error message");
      assert.strictEqual(
        message,
        `Unsupported algorithm: ${algorithm}`,
        "unexpected error message"
      );
    }
  });
});
