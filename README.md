# export-findmy

Export Apple Find My accessory keys from iCloud and write one **hass-FindMy-compatible `.json` file per device**.

This fork targets direct import into Home Assistant via `hass-FindMy`'s device-key upload. The generated files follow the current `FindMyAccessory.from_json(...)` schema used by `FindMy.py`/`hass-FindMy`. Most of the code was written by ChatGPT and has only been briefly checked. Use at your own risk!

## What it does

- signs into your Apple account
- joins the iCloud Keychain trust circle via an escrow bottle
- decrypts Find My accessory records from CloudKit
- writes one JSON file per accessory for direct upload into `hass-FindMy`

## Output format

Each exported device is written as a separate `.json` file containing:

- `type`
- `master_key`
- `skn`
- `sks`
- `paired_at`
- `name`
- `model`
- `identifier`
- `alignment_date`
- `alignment_index`

These files are intended for the `hass-FindMy` flow that says: **Upload your device keys in `.json` or `.plist` format.**

## Notable behavior in this fork

- exports **JSON**, not legacy plist output
- matches naming/alignment records by the CloudKit record ID used by `rustpush`
- writes unique filenames so devices do not overwrite each other
- hides password and passcode input via `rpassword`

## Prerequisites

- Rust toolchain
- `openssl` CLI
- `protoc`

On macOS:

```bash
brew install openssl protobuf
```

On Debian/Ubuntu:

```bash
sudo apt install build-essential pkg-config libssl-dev protobuf-compiler
```

On Windows, install:

- Rust
- OpenSSL development files usable by your Rust toolchain
- Protobuf / `protoc`

## Build

```bash
cargo build --release
```

## Usage

```bash
./target/release/export-findmy --apple-id you@example.com --output-dir ./keys
```

If you omit `--apple-id`, the tool prompts for it interactively.

Password and device-passcode entry are hidden. The 2FA code prompt remains visible.

Options:

- `--apple-id <email>` Apple ID email address
- `--anisette-url <url>` anisette server URL
- `--output-dir <dir>` output directory for generated JSON files

Default anisette URL:

```text
https://ani.sidestore.io
```

## Import into Home Assistant

1. Open the `hass-FindMy` integration.
2. Choose the option to upload device keys.
3. Upload one of the generated `.json` files.
4. Repeat for each accessory.

## Security

The generated JSON files contain sensitive key material. Treat them like secrets.

- Do not commit them to Git.
- Do not share them.
- Delete them when you no longer need them.

The tool also creates or updates local state files in the working directory:

- `keystore.plist` stores local keystore state used during keychain recovery.
- `anisette_state/` stores anisette provisioning/session state for the configured anisette backend.

These files are also sensitive and should be handled accordingly.

## Limits

- This project depends on `rustpush` and the current Find My / iCloud behavior.
- Some Apple device classes may expose incomplete metadata such as empty `model` strings or missing naming records.
- Shared items and unsupported device classes may still need additional handling.
