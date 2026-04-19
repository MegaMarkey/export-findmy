use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use keystore::{init_keystore, software::{NoEncryptor, SoftwareKeystore}};
use sha2::{Sha256, Digest};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteClient, ArcAnisetteClient};
use plist::Dictionary;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use rustpush::cloudkit::{
    pcs_keys_for_record, should_reset, CloudKitClient, CloudKitState,
    FetchRecordChangesOperation, NO_ASSETS,
};
use rustpush::cloudkit_proto::CloudKitRecord;
use rustpush::findmy::{
    BeaconNamingRecord, KeyAlignmentRecord, MasterBeaconRecord,
    SEARCH_PARTY_CONTAINER, FIND_MY_SERVICE,
};
use rustpush::keychain::{KeychainClient, KeychainClientState};
use rustpush::{
    login_apple_delegates, APSState, ActivationInfo, AppleAccount, DebugMutex, DebugRwLock,
    LoginDelegate, OSConfig, PushError, TokenProvider,
};
use rustpush::{DebugMeta, RegisterMeta};

// ── Fake OSConfig (presents as iPhone to avoid NAS validation) ───────


const DEFAULT_ANISETTE_URL: &str = "https://ani.sidestore.io";

#[derive(Clone)]
struct ExportedAccessory {
    record_id: String,
    master_record: MasterBeaconRecord,
    naming: BeaconNamingRecord,
    alignment: KeyAlignmentRecord,
}

struct FakeIOSConfig {
    device_uuid: String,
    serial: String,
    udid: String,
}

impl FakeIOSConfig {
    fn new() -> Self {
        FakeIOSConfig {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: "F2LZN0FAKE00".to_string(),
            udid: format!("{:032X}", rand::random::<u128>()),
        }
    }
}

#[async_trait]
impl OSConfig for FakeIOSConfig {
    fn build_activation_info(&self, _csr: Vec<u8>) -> ActivationInfo {
        unreachable!("activation not needed for FindMy export")
    }

    fn get_activation_device(&self) -> String {
        "iPhone".to_string()
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        Ok(vec![])
    }

    fn get_protocol_version(&self) -> u32 {
        1640
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: "iPhone15,2".to_string(),
            os_version: "iPhone OS,17.4,21E219".to_string(),
            software_version: "21E219".to_string(),
        }
    }

    fn get_normal_ua(&self, item: &str) -> String {
        format!("{item} CFNetwork/1494.0.7 Darwin/23.4.0")
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!("<iPhone15,2> <iPhone OS;17.4;21E219> <{}>", for_item)
    }

    fn get_version_ua(&self) -> String {
        "[iPhone OS,17.4,21E219,iPhone15,2]".to_string()
    }

    fn get_device_name(&self) -> String {
        "iPhone".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_uuid.clone()
    }

    fn get_private_data(&self) -> Dictionary {
        Dictionary::new()
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: "17.4".to_string(),
            hardware_version: "iPhone15,2".to_string(),
            serial_number: self.serial.clone(),
        }
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    }

    fn get_serial_number(&self) -> String {
        self.serial.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn get_aoskit_version(&self) -> String {
        "com.apple.AuthKit/1 (com.apple.akd/1.0)".to_string()
    }

    fn get_udid(&self) -> String {
        self.udid.clone()
    }
}

// ── JSON generation ─────────────────────────────────────────────────────

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn system_time_to_rfc3339(time: std::time::SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

fn format_optional_system_time(time: Option<std::time::SystemTime>) -> String {
    match time {
        Some(time) => system_time_to_rfc3339(time),
        None => "<none>".to_string(),
    }
}

fn debug_dump_accessory(acc: &ExportedAccessory) {
    eprintln!("  [debug] record_id={}", acc.record_id);
    eprintln!(
        "          stable_identifier={}",
        acc.master_record.stable_identifier
    );
    eprintln!(
        "          name={:?}, emoji={:?}, associated_beacon={}",
        acc.naming.name,
        acc.naming.emoji,
        acc.naming.associated_beacon
    );
    eprintln!(
        "          model={:?}, product_id={}, vendor_id={}, system_version={:?}",
        acc.master_record.model,
        acc.master_record.product_id,
        acc.master_record.vendor_id,
        acc.master_record.system_version
    );
    eprintln!(
        "          pairing_date={}, alignment_index={}, alignment_date={}",
        format_optional_system_time(acc.master_record.pairing_date),
        acc.alignment.last_index_observed,
        format_optional_system_time(acc.alignment.last_index_observation_date)
    );
    eprintln!(
        "          has_shared_secret_2={}, has_secure_locations_shared_secret={}",
        acc.master_record.shared_secret_2.is_some(),
        acc.master_record.secure_locations_shared_secret.is_some()
    );
}

fn sanitize_filename_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_was_sep = false;

    for ch in input.trim().chars() {
        let mapped = if ch.is_alphanumeric() || ch == '-' || ch == '_' {
            ch
        } else {
            '_'
        };

        if mapped == '_' {
            if !prev_was_sep {
                out.push(mapped);
            }
            prev_was_sep = true;
        } else {
            out.push(mapped);
            prev_was_sep = false;
        }
    }

    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "device".to_string()
    } else {
        out
    }
}

fn unique_output_path(
    output_dir: &Path,
    preferred_stem: &str,
    fallback_stem: &str,
    used_stems: &mut HashSet<String>,
) -> PathBuf {
    let preferred = sanitize_filename_component(preferred_stem);
    let fallback = sanitize_filename_component(fallback_stem);

    let base = if preferred == "device" { fallback } else { preferred };
    let mut candidate = base.clone();
    let mut suffix = 2usize;

    while used_stems.contains(&candidate) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }

    used_stems.insert(candidate.clone());
    output_dir.join(format!("{candidate}.json"))
}

fn accessory_to_findmy_json(acc: &ExportedAccessory) -> Result<Value, String> {
    let paired_at = acc
        .master_record
        .pairing_date
        .ok_or_else(|| format!("{}: missing pairing_date", acc.record_id))?;

    let private_key = &acc.master_record.private_key;
    if private_key.len() < 28 {
        return Err(format!(
            "{}: private_key too short ({} bytes)",
            acc.record_id,
            private_key.len()
        ));
    }
    let master_key = &private_key[private_key.len() - 28..];

    let secondary_secret = acc
        .master_record
        .shared_secret_2
        .as_ref()
        .or(acc.master_record.secure_locations_shared_secret.as_ref())
        .ok_or_else(|| format!("{}: missing secondary shared secret", acc.record_id))?;

    let alignment_date = acc
        .alignment
        .last_index_observation_date
        .or(acc.master_record.pairing_date);

    Ok(json!({
        "type": "accessory",
        "master_key": bytes_to_hex(master_key),
        "skn": bytes_to_hex(&acc.master_record.shared_secret),
        "sks": bytes_to_hex(secondary_secret),
        "paired_at": system_time_to_rfc3339(paired_at),
        "name": acc.naming.name.clone(),
        "model": acc.master_record.model.clone(),
        "identifier": acc.master_record.stable_identifier.clone(),
        "alignment_date": alignment_date.map(system_time_to_rfc3339),
        "alignment_index": acc.alignment.last_index_observed,
    }))
}

fn next_arg(args: &[String], i: &mut usize, flag: &str) -> Result<String, Box<dyn std::error::Error>> {
    *i += 1;
    if *i >= args.len() {
        return Err(format!("Missing value for {flag}").into());
    }
    Ok(args[*i].clone())
}

// ── Password reading ────────────────────────────────────────────────────

fn read_password() -> Result<String, Box<dyn std::error::Error>> {
    Ok(rpassword::read_password()?)
}

fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    read_password()
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    init_keystore(SoftwareKeystore {
        state: plist::from_file("keystore.plist").unwrap_or_default(),
        update_state: Box::new(|state| {
            if let Err(err) = plist::to_file_xml("keystore.plist", state) {
                eprintln!("Warning: failed to persist keystore.plist: {err}");
            }
        }),
        encryptor: NoEncryptor,
    });

    let args: Vec<String> = std::env::args().collect();

    let mut apple_id = String::new();
    let mut anisette_url = DEFAULT_ANISETTE_URL.to_string();
    let mut output_dir = PathBuf::from(".");
    let mut debug_records = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--apple-id" => {
                apple_id = next_arg(&args, &mut i, "--apple-id")?;
            }
            "--anisette-url" => {
                anisette_url = next_arg(&args, &mut i, "--anisette-url")?;
            }
            "--output-dir" => {
                output_dir = PathBuf::from(next_arg(&args, &mut i, "--output-dir")?);
            }
            "--debug-records" => {
                debug_records = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: export-findmy [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --apple-id <email>       Apple ID email");
                eprintln!("  --anisette-url <url>     Anisette server URL (default: {DEFAULT_ANISETTE_URL})");
                eprintln!("  --output-dir <dir>       Output directory for hass-FindMy JSON files (default: .)");
                eprintln!("  --debug-records          Print raw per-record metadata before JSON export");
                eprintln!();
                eprintln!("WARNING: Output JSON files contain private key material.");
                return Ok(());
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
        i += 1;
    }

    if apple_id.is_empty() {
        apple_id = prompt_line("Apple ID: ")?;
    }

    let password = prompt_password("Password: ")?;

    std::fs::create_dir_all(&output_dir)?;

    let config: Arc<dyn OSConfig> = Arc::new(FakeIOSConfig::new());

    // ── Step 1: Create anisette client ──────────────────────────────
    eprintln!("[1/7] Connecting to anisette server...");
    let anisette_config_path = PathBuf::from_str("anisette_state").unwrap();
    std::fs::create_dir_all(&anisette_config_path)?;

    let login_info = config.get_gsa_config(&APSState::default(), false);

    let anisette_client: ArcAnisetteClient<RemoteAnisetteProviderV3> =
        Arc::new(Mutex::new(AnisetteClient::new(
            RemoteAnisetteProviderV3::new(
                anisette_url.clone(),
                login_info.clone(),
                anisette_config_path,
            ),
        )));

    // ── Step 2: Login to Apple ──────────────────────────────────────
    eprintln!("[2/7] Logging in to Apple ID...");
    let apple_id_clone = apple_id.clone();
    let password_hash: Vec<u8> = Sha256::digest(password.as_bytes()).to_vec();
    let appleid_closure = move || (apple_id_clone.clone(), password_hash.clone());
    let tfa_closure = || {
        eprint!("2FA code: ");
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        match std::io::stdin().read_line(&mut input) {
            Ok(_) => input.trim().to_string(),
            Err(err) => {
                eprintln!("Failed to read 2FA code: {err}");
                String::new()
            }
        }
    };

    let account = AppleAccount::login(
        appleid_closure,
        tfa_closure,
        login_info,
        anisette_client.clone(),
    )
    .await?;

    let spd = account.spd.as_ref().expect("No SPD after login");
    let dsid = spd["DsPrsId"]
        .as_unsigned_integer()
        .unwrap()
        .to_string();
    let adsid = spd["adsid"].as_string().unwrap().to_string();

    eprintln!("  Logged in (dsid={})", dsid);

    // ── Step 3: Get MobileMe delegate ───────────────────────────────
    eprintln!("[3/7] Fetching MobileMe delegate...");
    let delegates = login_apple_delegates(
        &account,
        None,
        config.as_ref(),
        &[LoginDelegate::MobileMe],
    )
    .await?;
    let mobileme = delegates
        .mobileme
        .expect("No MobileMe delegate returned");

    // ── Step 4: Create CloudKit + Keychain clients ──────────────────
    eprintln!("[4/7] Setting up CloudKit & Keychain...");

    let keychain_state = KeychainClientState::new(dsid.clone(), adsid.clone(), &mobileme)
        .unwrap_or_else(|| {
            eprintln!("  (escrowProxyUrl not in MobileMe config, using default)");
            KeychainClientState::new_with_host(dsid.clone(), adsid.clone(), "https://p97-escrowproxy.icloud.com:443".to_string())
        });

    let account_arc = Arc::new(DebugMutex::new(account));
    let token_provider = TokenProvider::new(account_arc.clone(), config.clone());
    token_provider.set_mme_delegate(mobileme).await;

    let cloudkit_state =
        CloudKitState::new(dsid.clone()).expect("Failed to create CloudKitState");
    let cloudkit = Arc::new(CloudKitClient {
        state: DebugRwLock::new(cloudkit_state),
        anisette: anisette_client.clone(),
        config: config.clone(),
        token_provider: token_provider.clone(),
    });

    let keychain = Arc::new(KeychainClient {
        anisette: anisette_client.clone(),
        token_provider: token_provider.clone(),
        state: DebugRwLock::new(keychain_state),
        config: config.clone(),
        update_state: Box::new(|_| {}),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    // ── Step 5: Join iCloud Keychain circle via escrow ────────────
    eprintln!("[5/7] Joining iCloud Keychain trust circle...");
    let bottles = keychain.get_viable_bottles().await?;
    if bottles.is_empty() {
        return Err("No escrow bottles found. Make sure you have another trusted device.".into());
    }
    eprintln!("  Found {} escrow bottle(s):", bottles.len());
    for (i, (_, meta)) in bottles.iter().enumerate() {
        eprintln!("    [{}] {}", i, meta.serial);
    }
    let bottle_idx = if bottles.len() == 1 {
        0
    } else {
        let input = prompt_line("  Choose bottle [0]: ")?;
        let idx = input.trim().parse::<usize>().unwrap_or(0);
        if idx >= bottles.len() {
            return Err(format!("Invalid bottle index {}. Must be 0-{}.", idx, bottles.len() - 1).into());
        }
        idx
    };
    let (bottle, meta) = &bottles[bottle_idx];
    eprintln!("  Using escrow bottle from device: {}", meta.serial);
    let passcode = prompt_password("  Enter the passcode of that device: ")?;

    keychain
        .join_clique_from_escrow(bottle, passcode.as_bytes(), b"findmy-export")
        .await?;
    eprintln!("  Joined keychain trust circle!");

    // ── Step 6: Fetch BeaconStore records from CloudKit ─────────────
    eprintln!("[6/7] Fetching FindMy accessories from CloudKit...");

    let container = SEARCH_PARTY_CONTAINER
        .init(cloudkit.clone())
        .await?;
    let beacon_zone = container.private_zone("BeaconStore".to_string());
    let key = container
        .get_zone_encryption_config(&beacon_zone, &keychain, &FIND_MY_SERVICE)
        .await?;

    let mut beacon_records: HashMap<String, MasterBeaconRecord> = HashMap::new();
    let mut naming_records: HashMap<String, (String, BeaconNamingRecord)> = HashMap::new();
    let mut alignment_records: HashMap<String, (String, KeyAlignmentRecord)> = HashMap::new();

    let mut result = FetchRecordChangesOperation::do_sync(
        &container,
        &[(beacon_zone.clone(), None)],
        &NO_ASSETS,
    )
    .await;
    if should_reset(result.as_ref().err()) {
        result = FetchRecordChangesOperation::do_sync(
            &container,
            &[(beacon_zone.clone(), None)],
            &NO_ASSETS,
        )
        .await;
    }

    let (_, changes, _) = result?.remove(0);

    for change in changes {
        let Some(identifier) = change
            .identifier
            .as_ref()
            .and_then(|identifier| identifier.value.as_ref())
            .map(|value| value.name().to_string())
        else {
            eprintln!("  Skipping record change without identifier");
            continue;
        };

        let Some(record) = change.record else { continue };

        let Some(record_type) = record.r#type.as_ref().map(|record_type| record_type.name().to_string()) else {
            eprintln!("  Skipping record without type: {}", identifier);
            continue;
        };

        if record_type == MasterBeaconRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                MasterBeaconRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            beacon_records.insert(identifier, item);
        } else if record_type == BeaconNamingRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                BeaconNamingRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            naming_records.insert(
                item.associated_beacon.clone(),
                (identifier, item),
            );
        } else if record_type == KeyAlignmentRecord::record_type() {
            let pcs = pcs_keys_for_record(&record, &key)?;
            let item =
                KeyAlignmentRecord::from_record_encrypted(&record.record_field, Some(&pcs));
            alignment_records.insert(
                item.beacon_identifier.clone(),
                (identifier, item),
            );
        }
    }

    // ── Assemble accessories ────────────────────────────────────────
    let mut accessories: Vec<ExportedAccessory> = Vec::new();

    for (id, master) in beacon_records {
        let stable_id = master.stable_identifier.clone();

        let naming = naming_records.remove(&id).unwrap_or_else(|| {
            let short_stable = &stable_id[..8.min(stable_id.len())];
            let short_id = &id[..8.min(id.len())];
            (
                String::new(),
                BeaconNamingRecord {
                    emoji: "".to_string(),
                    name: format!("Unknown-{short_stable}-{short_id}"),
                    associated_beacon: id.clone(),
                    role_id: 0,
                },
            )
        });

        let alignment = alignment_records.remove(&id).unwrap_or_else(|| {
            (
                String::new(),
                KeyAlignmentRecord {
                    beacon_identifier: id.clone(),
                    last_index_observed: 0,
                    last_index_observation_date: master.pairing_date,
                },
            )
        });

        accessories.push(ExportedAccessory {
            record_id: id,
            master_record: master,
            naming: naming.1,
            alignment: alignment.1,
        });
    }

    // ── Step 7: Write hass-FindMy JSON files ────────────────────────
    eprintln!("[7/7] Writing hass-FindMy JSON files...");

    if accessories.is_empty() {
        eprintln!("  No accessories found!");
        return Ok(());
    }

    let mut used_stems = HashSet::new();
    let mut exported = 0usize;
    let mut skipped = 0usize;

    for acc in &accessories {
        if debug_records {
            debug_dump_accessory(acc);
        }

        let json = match accessory_to_findmy_json(acc) {
            Ok(json) => json,
            Err(err) => {
                skipped += 1;
                eprintln!("  Skipping {}: {}", acc.record_id, err);
                continue;
            }
        };

        let path = unique_output_path(
            &output_dir,
            &acc.naming.name,
            &format!("{}_{}", acc.master_record.stable_identifier, acc.record_id),
            &mut used_stems,
        );

        let file = std::fs::File::create(&path)?;
        serde_json::to_writer_pretty(file, &json)?;

        exported += 1;
        eprintln!(
            "  {} {} ({}) -> {}",
            acc.naming.emoji,
            acc.naming.name,
            acc.master_record.model,
            path.display()
        );
    }

    eprintln!();
    eprintln!(
        "Done! Exported {} hass-FindMy JSON file(s) to {}",
        exported,
        output_dir.display()
    );
    if skipped > 0 {
        eprintln!("Skipped {} accessory record(s) because required data was missing.", skipped);
    }

    Ok(())
}
