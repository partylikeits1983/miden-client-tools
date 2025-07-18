use miden_assembly::{
    Assembler, DefaultSourceManager, LibraryPath,
    ast::{Module, ModuleKind},
};
use miden_crypto::dsa::rpo_falcon512::Polynomial;
use rand::{RngCore, rngs::StdRng};
use std::sync::Arc;
use tokio::time::{Duration, sleep};

use miden_client::{
    Client, ClientError, Felt, Word,
    account::{
        Account, AccountBuilder, AccountId, AccountStorageMode, AccountType,
        component::{BasicFungibleFaucet, BasicWallet, RpoFalcon512},
    },
    asset::{Asset, FungibleAsset, TokenSymbol},
    auth::AuthSecretKey,
    builder::ClientBuilder,
    crypto::{FeltRng, SecretKey},
    keystore::FilesystemKeyStore,
    note::{
        Note, NoteAssets, NoteExecutionHint, NoteExecutionMode, NoteInputs, NoteMetadata,
        NoteRecipient, NoteScript, NoteTag, NoteType,
    },
    rpc::{Endpoint, TonicRpcClient},
    store::NoteFilter,
    transaction::{OutputNote, TransactionKernel, TransactionRequestBuilder, TransactionScript},
};
use miden_lib::note::utils;
use miden_objects::{Hasher, NoteError, assembly::Library};
use serde::de::value::Error;

/// Helper to instantiate a `Client` for interacting with Miden.
///
/// # Arguments
///
/// * `endpoint` - The endpoint of the RPC server to connect to.
/// * `store_path` - An optional path to the SQLite store.
///
/// # Returns
///
/// Returns a `Result` containing the `Client` if successful, or a `ClientError` if an error occurs.
pub async fn instantiate_client(
    endpoint: Endpoint,
    store_path: Option<&str>,
) -> Result<Client, ClientError> {
    let timeout_ms = 10_000;
    let rpc_api = Arc::new(TonicRpcClient::new(&endpoint, timeout_ms));

    let client = ClientBuilder::new()
        .rpc(rpc_api.clone())
        .filesystem_keystore("./keystore")
        .sqlite_store(store_path.unwrap_or("./store.sqlite3"))
        .in_debug_mode(true)
        .build()
        .await?;

    Ok(client)
}

/// Deletes the keystore and store files.
///
/// # Arguments
///
/// * `store_path` - An optional path to the SQLite store that should be deleted. Defaults to `./store.sqlite3` if not provided.
///
/// This function removes all files from the keystore and deletes the SQLite store file, if they exist.
pub async fn delete_keystore_and_store(store_path: Option<&str>) {
    let store_path = store_path.unwrap_or("./store.sqlite3");
    if tokio::fs::metadata(store_path).await.is_ok() {
        if let Err(e) = tokio::fs::remove_file(store_path).await {
            eprintln!("failed to remove {}: {}", store_path, e);
        } else {
            println!("cleared sqlite store: {}", store_path);
        }
    } else {
        println!("store not found: {}", store_path);
    }

    let keystore_dir = "./keystore";
    match tokio::fs::read_dir(keystore_dir).await {
        Ok(mut dir) => {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let file_path = entry.path();
                if let Err(e) = tokio::fs::remove_file(&file_path).await {
                    eprintln!("failed to remove {}: {}", file_path.display(), e);
                } else {
                    println!("removed file: {}", file_path.display());
                }
            }
        }
        Err(e) => eprintln!("failed to read directory {}: {}", keystore_dir, e),
    }
}

/// Multiplies two polynomials modulo `p` and returns the result.
///
/// # Arguments
///
/// * `a` - The first polynomial.
/// * `b` - The second polynomial.
///
/// # Returns
///
/// Returns the resulting polynomial of the multiplication.
const N: usize = 512;
fn mul_modulo_p(a: Polynomial<Felt>, b: Polynomial<Felt>) -> [u64; 1024] {
    let mut c = [0; 2 * N];
    for i in 0..N {
        for j in 0..N {
            c[i + j] += a.coefficients[i].as_int() * b.coefficients[j].as_int();
        }
    }
    c
}

/// Converts a polynomial into a vector of `Felt` elements.
///
/// # Arguments
///
/// * `poly` - The polynomial to convert.
///
/// # Returns
///
/// A vector of `Felt` elements corresponding to the polynomial's coefficients.
fn to_elements(poly: Polynomial<Felt>) -> Vec<Felt> {
    poly.coefficients.to_vec()
}

/// Generates an advice stack from a signature using two polynomials `h` and `s2`.
///
/// # Arguments
///
/// * `h` - The first polynomial representing part of the signature.
/// * `s2` - The second polynomial representing part of the signature.
///
/// # Returns
///
/// Returns a vector representing the advice stack.
pub fn generate_advice_stack_from_signature(h: Polynomial<Felt>, s2: Polynomial<Felt>) -> Vec<u64> {
    let pi = mul_modulo_p(h.clone(), s2.clone());

    // lay the polynomials in order h then s2 then pi = h * s2
    let mut polynomials = to_elements(h.clone());
    polynomials.extend(to_elements(s2.clone()));
    polynomials.extend(pi.iter().map(|a| Felt::new(*a)));

    // get the challenge point and push it to the advice stack
    let digest_polynomials = Hasher::hash_elements(&polynomials);
    let challenge = (digest_polynomials[0], digest_polynomials[1]);
    let mut advice_stack = vec![challenge.0.as_int(), challenge.1.as_int()];

    // push the polynomials to the advice stack
    let polynomials: Vec<u64> = polynomials.iter().map(|&e| e.into()).collect();
    advice_stack.extend_from_slice(&polynomials);

    advice_stack
}

/// Creates a Miden library from the provided account code and library path.
///
/// # Arguments
///
/// * `account_code` - The account code in MASM format.
/// * `library_path` - The path where the library is located.
///
/// # Returns
///
/// Returns the resulting `Library` if successful, or an error if the library cannot be created.
pub fn create_library(
    account_code: String,
    library_path: &str,
) -> Result<miden_assembly::Library, Box<dyn std::error::Error>> {
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(ModuleKind::Library).parse_str(
        LibraryPath::new(library_path)?,
        account_code,
        &source_manager,
    )?;
    let library = assembler.clone().assemble_library([module])?;
    Ok(library)
}

/// Creates a basic account with a random key and adds it to the client.
///
/// # Arguments
///
/// * `client` - The Miden client to interact with.
/// * `keystore` - The keystore to store the account's secret key.
///
/// # Returns
///
/// Returns a tuple containing the created `Account` and the associated `SecretKey`.
pub async fn create_basic_account(
    client: &mut Client,
    keystore: FilesystemKeyStore<StdRng>,
) -> Result<(miden_client::account::Account, SecretKey), ClientError> {
    let mut init_seed = [0_u8; 32];
    client.rng().fill_bytes(&mut init_seed);

    let key_pair = SecretKey::with_rng(client.rng());
    let builder = AccountBuilder::new(init_seed)
        // .anchor((&anchor_block).try_into().unwrap())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(RpoFalcon512::new(key_pair.public_key().clone()))
        .with_component(BasicWallet);

    let (account, seed) = builder.build().unwrap();
    client.add_account(&account, Some(seed), false).await?;
    keystore
        .add_key(&AuthSecretKey::RpoFalcon512(key_pair.clone()))
        .unwrap();

    Ok((account, key_pair))
}

/// Creates a basic faucet account with a fungible asset.
///
/// # Arguments
///
/// * `client` - The Miden client to interact with.
/// * `keystore` - The keystore to store the faucet's secret key.
///
/// # Returns
///
/// Returns the created faucet `Account`.
pub async fn create_basic_faucet(
    client: &mut Client,
    keystore: FilesystemKeyStore<StdRng>,
) -> Result<miden_client::account::Account, ClientError> {
    let mut init_seed = [0u8; 32];
    client.rng().fill_bytes(&mut init_seed);
    let key_pair = SecretKey::with_rng(client.rng());
    let symbol = TokenSymbol::new("MID").unwrap();
    let decimals = 8;
    let max_supply = Felt::new(1_000_000);
    let builder = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(RpoFalcon512::new(key_pair.public_key()))
        .with_component(BasicFungibleFaucet::new(symbol, decimals, max_supply).unwrap());
    let (account, seed) = builder.build().unwrap();
    client.add_account(&account, Some(seed), false).await?;
    keystore
        .add_key(&AuthSecretKey::RpoFalcon512(key_pair))
        .unwrap();
    Ok(account)
}

/// Sets up a specified number of accounts and faucets, and mints tokens for each account.
///
/// This function creates a set of basic accounts and faucets, and mints tokens from each faucet to the accounts
/// based on the given balance matrix.
///
/// # Arguments
///
/// * `client` - The Miden client used to interact with the blockchain.
/// * `keystore` - The keystore used to securely store account keys.
/// * `num_accounts` - The number of accounts to create.
/// * `num_faucets` - The number of faucets to create.
/// * `balances` - A matrix where each entry represents the number of tokens to mint from a faucet to an account.
///
/// # Returns
///
/// Returns a tuple containing the created accounts and faucets as vectors.
pub async fn setup_accounts_and_faucets(
    client: &mut Client,
    keystore: FilesystemKeyStore<StdRng>,
    num_accounts: usize,
    num_faucets: usize,
    balances: Vec<Vec<u64>>,
) -> Result<(Vec<Account>, Vec<Account>), ClientError> {
    let mut accounts = Vec::with_capacity(num_accounts);
    for i in 0..num_accounts {
        let (account, _) = create_basic_account(client, keystore.clone()).await?;
        println!("Created Account #{i} => ID: {:?}", account.id());
        accounts.push(account);
    }

    let mut faucets = Vec::with_capacity(num_faucets);
    for j in 0..num_faucets {
        let faucet = create_basic_faucet(client, keystore.clone()).await?;
        println!("Created Faucet #{j} => ID: {:?}", faucet.id());
        faucets.push(faucet);
    }

    client.sync_state().await?;

    for (acct_index, account) in accounts.iter().enumerate() {
        for (faucet_index, faucet) in faucets.iter().enumerate() {
            let amount_to_mint = balances[acct_index][faucet_index];
            if amount_to_mint == 0 {
                continue;
            }

            println!(
                "Minting {amount_to_mint} tokens from Faucet #{faucet_index} to Account #{acct_index}"
            );

            let fungible_asset = FungibleAsset::new(faucet.id(), amount_to_mint).unwrap();
            let tx_req = TransactionRequestBuilder::new()
                .build_mint_fungible_asset(
                    fungible_asset,
                    account.id(),
                    NoteType::Public,
                    client.rng(),
                )
                .unwrap();

            let tx_exec = client.new_transaction(faucet.id(), tx_req).await?;
            client.submit_transaction(tx_exec.clone()).await?;

            let minted_note = if let OutputNote::Full(note) = tx_exec.created_notes().get_note(0) {
                note.clone()
            } else {
                panic!("Expected OutputNote::Full, but got something else");
            };

            wait_for_note(client, &minted_note).await?;
            client.sync_state().await?;

            let consume_req = TransactionRequestBuilder::new()
                .authenticated_input_notes([(minted_note.id(), None)])
                .build()
                .unwrap();

            let tx_exec = client.new_transaction(account.id(), consume_req).await?;
            client.submit_transaction(tx_exec).await?;
            client.sync_state().await?;
        }
    }

    Ok((accounts, faucets))
}

/// Mints tokens from a faucet to an account.
///
/// This function mints a specified amount of tokens from a faucet to an account, and waits for the transaction
/// to be confirmed. It optionally executes a custom transaction script if provided.
///
/// # Arguments
///
/// * `client` - The Miden client used to interact with the blockchain.
/// * `account` - The account that will receive the tokens.
/// * `faucet` - The faucet to mint tokens from.
/// * `amount` - The number of tokens to mint.
/// * `tx_script` - An optional custom transaction script to execute after the minting transaction. If `None`, no script is executed.
///
/// # Returns
///
/// Returns a `Result` indicating whether the minting process was successful or not. If the transaction script is provided, it will also be executed
/// after the minting process, otherwise, only the minting transaction is processed.
pub async fn mint_from_faucet_for_account(
    client: &mut Client,
    account: &Account,
    faucet: &Account,
    amount: u64,
    tx_script: Option<TransactionScript>, // Make tx_script optional
) -> Result<(), ClientError> {
    if amount == 0 {
        return Ok(());
    }

    let asset = FungibleAsset::new(faucet.id(), amount).unwrap();
    let mint_req = TransactionRequestBuilder::new()
        .build_mint_fungible_asset(asset, account.id(), NoteType::Public, client.rng())
        .unwrap();

    let mint_exec = client.new_transaction(faucet.id(), mint_req).await?;
    client.submit_transaction(mint_exec.clone()).await?;

    let minted_note = match mint_exec.created_notes().get_note(0) {
        OutputNote::Full(note) => note.clone(),
        _ => panic!("Expected full minted note"),
    };

    let consume_req = if let Some(script) = tx_script {
        TransactionRequestBuilder::new()
            .unauthenticated_input_notes([(minted_note, None)])
            .custom_script(script)
            .build()?
    } else {
        TransactionRequestBuilder::new()
            .unauthenticated_input_notes([(minted_note, None)])
            .build()?
    };

    let consume_exec = client
        .new_transaction(account.id(), consume_req)
        .await
        .unwrap();

    client.submit_transaction(consume_exec.clone()).await?;
    client.sync_state().await?;

    Ok(())
}

/// Creates a public note in the blockchain.
///
/// This function creates a public note using the provided note code, account library (if any), and other
/// related parameters.
///
/// # Arguments
///
/// * `client` - The Miden client used to interact with the blockchain.
/// * `note_code` - The code for the note, typically written in MASM.
/// * `account_library` - An optional library that might be used during note creation.
/// * `creator_account` - The account creating the note.
/// * `assets` - The assets associated with the note (optional).
/// * `note_inputs` - The inputs associated with the note (optional).
///
/// # Returns
///
/// Returns a `Result` containing the created `Note` or an error.
pub async fn create_public_note(
    client: &mut Client,
    note_code: String,
    account_library: Option<Library>,
    creator_account: Account,
    assets: Option<NoteAssets>,
    note_inputs: Option<NoteInputs>,
) -> Result<Note, ClientError> {
    let assembler = if let Some(library) = account_library {
        TransactionKernel::assembler()
            .with_library(&library)
            .unwrap()
    } else {
        TransactionKernel::assembler()
    }
    .with_debug_mode(true);

    let rng = client.rng();
    let serial_num = rng.draw_word();
    let note_script = NoteScript::compile(note_code, assembler.clone()).unwrap();

    let note_inputs = note_inputs.unwrap_or_else(|| NoteInputs::new([].to_vec()).unwrap());
    let assets = assets.unwrap_or_else(|| NoteAssets::new(vec![]).unwrap());

    let recipient = NoteRecipient::new(serial_num, note_script, note_inputs.clone());
    let tag = NoteTag::for_public_use_case(0, 0, NoteExecutionMode::Local).unwrap();
    let metadata = NoteMetadata::new(
        creator_account.id(),
        NoteType::Public,
        tag,
        NoteExecutionHint::always(),
        Felt::new(0),
    )
    .unwrap();

    let note = Note::new(assets, metadata, recipient);

    let note_req = TransactionRequestBuilder::new()
        .own_output_notes(vec![OutputNote::Full(note.clone())])
        .build()
        .unwrap();
    let tx_result = client
        .new_transaction(creator_account.id(), note_req)
        .await?;

    client.submit_transaction(tx_result).await?;
    client.sync_state().await?;

    Ok(note)
}

/// Waits for the exact note to be available and committed.
///
/// This function will block until the specified note is found in the output notes and is committed.
///
/// # Arguments
///
/// * `client` - The Miden client used to interact with the blockchain.
/// * `expected` - The note to wait for.
///
/// # Returns
///
/// Returns a `Result` indicating whether the note was found and committed.
pub async fn wait_for_note(client: &mut Client, expected: &Note) -> Result<(), ClientError> {
    loop {
        client.sync_state().await?;

        let notes = client.get_output_notes(NoteFilter::All).await?;

        // Check if the expected note is in the output notes and is committed
        let found = notes
            .iter()
            .any(|output_note| output_note.id() == expected.id() && output_note.is_committed());

        if found {
            println!("✅ note found and committed {}", expected.id().to_hex());
            break;
        }

        println!("Note {} not found. Waiting...", expected.id().to_hex());
        sleep(Duration::from_secs(3)).await;
    }
    Ok(())
}

/// Creates a transaction script based on the provided code and optional library.
///
/// # Arguments
///
/// * `script_code` - The code for the transaction script, typically written in MASM.
/// * `library` - An optional library to use with the script.
///
/// # Returns
///
/// Returns a `TransactionScript` if successfully created, or an error.
pub fn create_tx_script(
    script_code: String,
    library: Option<Library>,
) -> Result<TransactionScript, Error> {
    let assembler = TransactionKernel::assembler();

    let assembler = match library {
        Some(lib) => assembler.with_library(lib),
        None => Ok(assembler.with_debug_mode(true)),
    }
    .unwrap();
    let tx_script = TransactionScript::compile(script_code, assembler).unwrap();

    Ok(tx_script)
}

/// Creates a public-to-ID (p2id) note for a specified sender and target account.
///
/// # Arguments
///
/// * `sender` - The account ID of the sender.
/// * `target` - The account ID of the target.
/// * `assets` - The assets associated with the note.
/// * `note_type` - The type of the note (e.g., public).
/// * `aux` - Auxiliary data for the note.
/// * `serial_num` - The serial number of the note.
///
/// # Returns
///
/// Returns the created `Note`.
pub fn create_exact_p2id_note(
    sender: AccountId,
    target: AccountId,
    assets: Vec<Asset>,
    note_type: NoteType,
    aux: Felt,
    serial_num: Word,
) -> Result<Note, NoteError> {
    let recipient = utils::build_p2id_recipient(target, serial_num)?;
    let tag = NoteTag::from_account_id(target);

    let metadata = NoteMetadata::new(sender, note_type, tag, NoteExecutionHint::always(), aux)?;
    let vault = NoteAssets::new(assets)?;

    Ok(Note::new(vault, metadata, recipient))
}
