# Vault

A local-first password manager built with Expo and React Native.

> **Status:** Experimental. Do not use this app to store important passwords, recovery phrases, or other sensitive information until it has been independently reviewed and tested.

## Features

- Create and unlock a local vault with a master password
- Encrypt stored entries using XChaCha20-Poly1305
- Derive encryption keys from the master password with scrypt
- Store passwords and recovery phrases
- Generate random passwords
- Search, edit, delete, reveal, and copy entries
- Automatically lock when the app goes into the background or remains idle
- Export and import encrypted backups

## Tech stack

- Expo SDK 57
- React Native
- React Native Web
- `@noble/ciphers`
- `@noble/hashes`
- AsyncStorage

## Getting started

### Prerequisites

- Node.js
- npm
- Expo-compatible development environment, or Expo Go where supported

### Install dependencies

```bash
npm install
```

### Start the development server

```bash
npm start
```

You can also run the platform-specific scripts:

```bash
npm run android
npm run ios
npm run web
```

## Security notes

- Vault contents are encrypted locally and are not sent to a server by this app.
- The master password cannot be recovered if it is forgotten.
- Encrypted backups should still be handled carefully because anyone who obtains one can attempt offline password guessing.
- Never commit real passwords, recovery phrases, API keys, `.env` files, signing keys, or other credentials to this repository.
- This project has not received a formal security audit.

## Project structure

- `App.js` — application UI, vault logic, encryption, backup, and auto-lock behavior
- `app.json` — Expo application configuration
- `assets/` — application icons and splash assets
- `index.js` — application entry point

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
