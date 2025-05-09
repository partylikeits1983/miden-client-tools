# miden-client-tools

`miden-client-tools` is a wrapper around the Miden client that simplifies interactions with the Miden blockchain. It provides convenient functions for creating accounts, managing faucets, minting tokens, and interacting with the Miden client.

This library aims to make it easier for developers to work with Miden by providing a higher-level interface on top of the core Miden client, removing the need for boilerplate code in common use cases.

## Features

- **Account Management**: Create and manage accounts, including basic accounts and faucet accounts.
- **Token Minting**: Mint tokens from faucets to user accounts.
- **Library Creation**: Easily create and deploy Miden libraries.
- **Transaction Management**: Handle Miden transactions for minting and consuming notes.
- **Keystore & Store Management**: Automatically manage keystores and SQLite stores.

### Testing locally:

Running all tests sequentially:
```
cargo test --release -- --test-threads=1
```

Running single test:
```
cargo test --release --package miden-client-tools --test tools_tests -- tests::test_create_public_note --exact --show-output
```