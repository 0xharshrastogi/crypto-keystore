# crypto-keystore

A lightweight, cross-platform keystore cryptographic utility library for secure data storage and encryption.

## Features

- **Cross-Platform Compatibility**: Seamlessly works in both Node.js and browser environments.
- **Secure Cryptographic Operations**: Ensures the integrity and confidentiality of your data.
- **TypeScript Support**: Built with TypeScript for robust code quality and maintainability.

## Installation

```bash
npm install crypto-keystore
# or
pnpm add crypto-keystore
# or
yarn add crypto-keystore
```

## Usage

```typescript
import { encrypt, decrypt } from 'crypto-keystore';

const message = "Hello, World!";
const password = "password";

const keystore = await encrypt(
      new TextEncoder().encode(message),
      "aes-128-ctr",
      password
);

console.log(keystore); // { ... }
```
