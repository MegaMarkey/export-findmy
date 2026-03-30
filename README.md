# export-findmy

Export AirTag/FindMy accessory private keys from iCloud, producing `.plist` files compatible with [FindMy.py](https://github.com/malmeloo/FindMy.py).

Works on any platform — no Mac key extraction tools needed. Useful when macOS breaks existing methods (as happened with macOS 26).

## Prerequisites

- [Rust toolchain](https://rustup.rs/)
- `openssl` CLI (for building — generates dummy FairPlay certs needed by rustpush)
- `protoc` (protobuf compiler) — `brew install protobuf` on macOS

## Build

```bash
git clone https://github.com/thisiscam/export-findmy.git
cd export-findmy
cargo build --release
```

## Usage

```bash
./target/release/export-findmy \
  --apple-id you@example.com \
  --output-dir ./keys
```

The tool will prompt for:
1. **Password** (hidden input)
2. **2FA code** — enter the **SMS code** sent to your phone, not the code shown on other devices
3. **Device passcode** — the screen lock passcode (iPhone PIN) or login password (Mac) of the device listed

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--apple-id <email>` | Apple ID email | prompted if omitted |
| `--anisette-url <url>` | Anisette v3 server URL | `https://ani.sidestore.io` |
| `--output-dir <dir>` | Where to write plist files | `.` |

### Example

```
$ ./target/release/export-findmy --apple-id jq.yang@berkeley.edu --output-dir ./keys
Password:
[1/7] Connecting to anisette server...
[2/7] Logging in to Apple ID...
2FA code: 123456
  Logged in (dsid=1826840088)
[3/7] Fetching MobileMe delegate...
[4/7] Setting up CloudKit & Keychain...
[5/7] Joining iCloud Keychain trust circle...
  Found 1 escrow bottle(s):
    [0] L2MPKH342P
  Using escrow bottle from device: L2MPKH342P
  Enter the passcode of that device:
  Joined keychain trust circle!
[6/7] Fetching FindMy accessories from CloudKit...
[7/7] Writing plist files...
  🎧 Wilbur's AirTag (AirTag) -> ./keys/Wilbur_s_AirTag.plist

Done! Exported 1 accessory plist file(s) to ./keys
```

## Output format

Each accessory produces a `.plist` file containing:

| Key | Description |
|-----|-------------|
| `privateKey` | EC private key (for deriving rolling BLE keys) |
| `sharedSecret` | Primary shared secret |
| `secondarySharedSecret` | Secondary shared secret (if present) |
| `publicKey` | EC public key |
| `identifier` | Stable accessory identifier |
| `name` | User-assigned name |
| `emoji` | User-assigned emoji |
| `model` | Hardware model |
| `pairingDate` | When the accessory was paired |

These files can be used directly with [FindMy.py](https://github.com/malmeloo/FindMy.py) for tracking AirTag locations.

## Security notes

- **Output plist files contain private key material.** Treat them like passwords.
- Your Apple ID password and device passcode are never written to disk.
- `anisette_state/` and `keystore.plist` are created in the working directory at runtime — these contain device provisioning state and keychain crypto keys. Delete them after use if you don't plan to run the tool again.
- The anisette server only sees OTP header requests from your IP. It never sees your Apple ID, password, or iCloud data.

## How it works

1. Authenticates to Apple via SRP (using remote anisette for device identity tokens)
2. Fetches MobileMe delegate tokens via the iOS `iosbuddy` login endpoint
3. Joins the iCloud Keychain trust circle via escrow recovery (using your device passcode)
4. Fetches encrypted `BeaconStore` records from CloudKit
5. Decrypts records using PCS (Protected CloudStorage) keys from the keychain
6. Writes accessory data to plist files

Built on [rustpush](https://github.com/OpenBubbles/rustpush) by the OpenBubbles project.
