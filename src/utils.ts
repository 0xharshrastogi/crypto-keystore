export const encodeText = (text: string) => new TextEncoder().encode(text);

export const decodeText = (bytes: Uint8Array) =>
  new TextDecoder().decode(bytes);
