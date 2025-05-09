use miden_client_tools::{
    create_basic_account, create_exact_p2id_note, create_public_note, delete_keystore_and_store,
    instantiate_client, mint_from_faucet_for_account, setup_accounts_and_faucets, wait_for_note,
    wait_for_notes,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;
    use miden_client::rpc::Endpoint;
    use miden_client::{account::AccountId, keystore::FilesystemKeyStore, note::NoteType};
    use miden_client_tools::{create_basic_faucet, create_library, create_tx_script};
    use miden_crypto::{Felt, Word};

    #[tokio::test]
    async fn test_instantiate_client_with_default_store() {
        let endpoint = Endpoint::localhost();
        let client = instantiate_client(endpoint, None).await;

        assert!(client.is_ok());

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_instantiate_client_with_custom_store() {
        let endpoint = Endpoint::localhost();
        let store_path = "./custom_store.sqlite3";
        let client = instantiate_client(endpoint, Some(store_path)).await;

        assert!(client.is_ok());

        delete_keystore_and_store(Some(store_path)).await;
    }

    #[tokio::test]
    async fn test_delete_keystore_and_store_existing_file() {
        let store_path = "./store.sqlite3";

        let endpoint = Endpoint::localhost();
        let _client = instantiate_client(endpoint, Some(store_path)).await;

        delete_keystore_and_store(Some(store_path)).await;

        let metadata = tokio::fs::metadata(store_path).await;
        assert!(metadata.is_err());
    }

    #[tokio::test]
    async fn test_delete_keystore_and_store_non_existing_file() {
        let store_path = "./non_existing_store.sqlite3";
        delete_keystore_and_store(Some(store_path)).await;

        let metadata = tokio::fs::metadata(store_path).await;
        assert!(metadata.is_err());
    }

    #[tokio::test]
    async fn test_create_library() {
        let account_code = fs::read_to_string(Path::new("./masm/accounts/counter.masm")).unwrap();
        let library_path = "external_contract::counter_contract";
        let library = create_library(account_code, library_path);

        assert!(
            library.is_ok(),
            "Library creation failed: {:?}",
            library.err()
        );
    }

    #[tokio::test]
    async fn test_create_basic_account() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let (account, _) = create_basic_account(&mut client, keystore).await.unwrap();
        assert_eq!(account.id().to_string().len(), 32);

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_create_basic_faucet() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let faucet = create_basic_faucet(&mut client, keystore).await.unwrap();
        assert_eq!(faucet.id().to_string().len(), 32);
    }

    #[tokio::test]
    async fn test_setup_accounts_and_faucets() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let balances = vec![vec![10, 20], vec![30, 40]];
        let (accounts, faucets) = setup_accounts_and_faucets(&mut client, keystore, 2, 2, balances)
            .await
            .unwrap();

        assert_eq!(accounts.len(), 2);
        assert_eq!(faucets.len(), 2);

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_mint_from_faucet_for_account() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        client.sync_state().await.unwrap();

        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let (account, _) = create_basic_account(&mut client, keystore.clone())
            .await
            .unwrap();
        let faucet = create_basic_faucet(&mut client, keystore).await.unwrap();

        let result = mint_from_faucet_for_account(&mut client, &account, &faucet, 100).await;
        assert!(result.is_ok());

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_create_public_note() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        client.sync_state().await.unwrap();

        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let (account, _) = create_basic_account(&mut client, keystore).await.unwrap();

        let note_code = fs::read_to_string(Path::new("./masm/notes/increment_note.masm")).unwrap();

        let account_code = fs::read_to_string(Path::new("./masm/accounts/counter.masm")).unwrap();
        let library_path = "external_contract::counter_contract";
        let library = create_library(account_code, library_path).unwrap();

        let note = create_public_note(
            &mut client,
            note_code,
            Some(library),
            account.clone(),
            None,
            None,
        )
        .await
        .unwrap();

        let result = wait_for_note(&mut client, &account, &note).await;

        assert!(result.is_ok());

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_wait_for_notes() {
        let endpoint = Endpoint::localhost();
        let mut client = instantiate_client(endpoint, None).await.unwrap();
        client.sync_state().await.unwrap();

        let keystore = FilesystemKeyStore::new("./keystore".into()).unwrap();

        let (account, _) = create_basic_account(&mut client, keystore).await.unwrap();

        let note_code = fs::read_to_string(Path::new("./masm/notes/increment_note.masm")).unwrap();

        let account_code = fs::read_to_string(Path::new("./masm/accounts/counter.masm")).unwrap();
        let library_path = "external_contract::counter_contract";
        let library = create_library(account_code, library_path).unwrap();

        let _note = create_public_note(
            &mut client,
            note_code,
            Some(library),
            account.clone(),
            None,
            None,
        )
        .await
        .unwrap();

        let result = wait_for_notes(&mut client, &account, 1).await;
        assert!(result.is_ok());

        delete_keystore_and_store(None).await;
    }

    #[tokio::test]
    async fn test_create_tx_script() {
        let script_code =
            fs::read_to_string(Path::new("./masm/scripts/increment_script.masm")).unwrap();
        let account_code = fs::read_to_string(Path::new("./masm/accounts/counter.masm")).unwrap();
        let library_path = "external_contract::counter_contract";
        let library = create_library(account_code, library_path).unwrap();
        let tx_script = create_tx_script(script_code, Some(library));

        assert!(tx_script.is_ok());
    }

    #[tokio::test]
    async fn test_create_exact_p2id_note() {
        let sender = AccountId::from_hex("0x4eef4d8ee35714200009819615ca84").unwrap();
        let target = AccountId::from_hex("0x1478f6f84363ed200009ce915221a6").unwrap();
        let assets = vec![];
        let note_type = NoteType::Public;
        let aux = Felt::new(0);
        let serial_num = Word::default();

        let note = create_exact_p2id_note(sender, target, assets, note_type, aux, serial_num);
        assert!(note.is_ok());
    }
}
