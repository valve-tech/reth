//! E2E tests for SELFDESTRUCT behavior and output state verification.
//!
//! These tests verify that:
//! - Pre-Dencun: SELFDESTRUCT clears storage and code, output state reflects this
//! - Post-Dencun (EIP-6780): SELFDESTRUCT only works in same-tx creation, state persists
//!
//! We disable prewarming to ensure deterministic cache behavior and verify the execution
//! output state contains the expected account status after SELFDESTRUCT.

use alloy_primitives::{bytes, Bytes, U256};
use alloy_provider::Provider;
use reth_chainspec::EthereumHardfork;
use reth_e2e_test_utils::{wallet::Wallet, E2ETestSetupExt, NodeHelperType};
use reth_node_ethereum::EthereumNode;

/// Launches a node for the given hardfork with prewarming disabled, so the execution output state
/// is deterministic.
async fn setup_node(
    fork: EthereumHardfork,
) -> eyre::Result<(NodeHelperType<EthereumNode>, Wallet)> {
    EthereumNode::test_setup_for(fork)
        .with_tree_config_modifier(|config| {
            config.without_prewarming(true).without_state_cache(false)
        })
        .build_single()
        .await
}

/// Creates init code for a contract that selfdestructs during deployment (same tx).
/// This tests the EIP-6780 exception where SELFDESTRUCT in same tx as creation still works.
///
/// The contract:
/// 1. Stores 0x42 at slot 0
/// 2. Immediately selfdestructs to beneficiary (during init, before returning runtime)
fn selfdestruct_in_constructor_init_code() -> Bytes {
    // Init code that selfdestructs during deployment:
    // PUSH1 0x42, PUSH1 0x00, SSTORE  (store 0x42 at slot 0)
    // PUSH20 <beneficiary>, SELFDESTRUCT
    let mut init = Vec::new();
    init.extend_from_slice(&[0x60, 0x42, 0x60, 0x00, 0x55]); // PUSH1 0x42, PUSH1 0x00, SSTORE
    init.extend_from_slice(&[
        0x73, // PUSH20
        0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, // beneficiary address
    ]);
    init.push(0xff); // SELFDESTRUCT

    Bytes::from(init)
}

/// Creates init code for a simple contract that:
/// 1. Stores 0x42 at slot 0 during deployment
/// 2. On any call: selfdestructs to beneficiary
///
/// This simpler contract avoids complex branching logic.
fn selfdestruct_contract_init_code() -> Bytes {
    // Runtime: just selfdestruct on any call
    // PUSH20 <beneficiary>
    // SELFDESTRUCT
    let runtime = bytes!(
        "73dead000000000000000000000000000000000001" // PUSH20 beneficiary
        "ff"       // SELFDESTRUCT
    );

    let runtime_len = runtime.len(); // 22 bytes

    // Init code: SSTORE(0, 0x42), CODECOPY, RETURN
    // Total init code before runtime = 17 bytes
    let init_len: u8 = 17;

    let mut init = Vec::new();
    init.extend_from_slice(&[0x60, 0x42, 0x60, 0x00, 0x55]); // PUSH1 0x42, PUSH1 0x00, SSTORE
    init.extend_from_slice(&[0x60, runtime_len as u8, 0x60, init_len, 0x60, 0x00, 0x39]); // CODECOPY
    init.extend_from_slice(&[0x60, runtime_len as u8, 0x60, 0x00, 0xf3]); // RETURN
    init.extend_from_slice(&runtime);

    Bytes::from(init)
}

/// Tests SELFDESTRUCT behavior post-Dencun (Cancun+).
///
/// Post-Dencun (EIP-6780):
/// - SELFDESTRUCT only deletes contract if called in same tx as creation
/// - For existing contracts, SELFDESTRUCT only sends balance, code/storage persist
/// - The output state should NOT mark the account as destroyed
///
/// This test verifies:
/// 1. Contract deploys with storage
/// 2. SELFDESTRUCT in later tx does NOT delete code/storage
/// 3. Output state shows account is NOT destroyed
#[tokio::test]
async fn test_selfdestruct_post_dencun() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, wallet) = setup_node(EthereumHardfork::Cancun).await?;
    let mut account = wallet.account(0);
    let provider = node.rpc_provider();

    // Deploy contract that stores 0x42 at slot 0 and selfdestructs on any call
    let deploy = account.deploy(selfdestruct_contract_init_code()).await;
    let mined = node.mine([deploy]).await?.ensure_success()?;
    let contract_address =
        mined.receipts[0].contract_address.expect("Should have contract address");

    // Trigger SELFDESTRUCT by calling the contract
    let mined = node.mine([account.tx().to(contract_address).await]).await?.ensure_success()?;
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state: post-Dencun, account should NOT be destroyed
    let account_state = execution_outcome.account(&contract_address);
    assert!(
        !matches!(account_state, Some(None)),
        "Post-Dencun (EIP-6780): Account should NOT be destroyed when SELFDESTRUCT called on existing contract"
    );

    // Verify via RPC that code and storage persist
    let code_after = provider.get_code_at(contract_address).await?;
    assert!(!code_after.is_empty(), "Post-Dencun: Contract code should persist");

    let slot0_after = provider.get_storage_at(contract_address, U256::ZERO).await?;
    assert_eq!(slot0_after, U256::from(0x42), "Post-Dencun: Storage should persist");

    // Send another transaction to the contract address in a new block.
    // This tests cache behavior - if cache has stale data, execution would be incorrect.
    // Post-Dencun: calling the contract should trigger SELFDESTRUCT again (but only transfer
    // balance)
    let mined = node.mine([account.tx().to(contract_address).await]).await?.ensure_success()?;
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state still shows account NOT destroyed
    let account_state = execution_outcome.account(&contract_address);
    assert!(
        !matches!(account_state, Some(None)),
        "Post-Dencun: Account should still NOT be destroyed after second SELFDESTRUCT call"
    );

    // Verify code and storage still persist after the second call
    let code_final = provider.get_code_at(contract_address).await?;
    assert!(!code_final.is_empty(), "Post-Dencun: Contract code should still persist");

    let slot0_final = provider.get_storage_at(contract_address, U256::ZERO).await?;
    assert_eq!(slot0_final, U256::from(0x42), "Post-Dencun: Storage should still persist");

    Ok(())
}

/// Tests SELFDESTRUCT in same transaction as creation (post-Dencun).
///
/// Post-Dencun (EIP-6780):
/// - SELFDESTRUCT during the same transaction as creation DOES delete the contract
/// - This is the exception to the rule that SELFDESTRUCT no longer deletes contracts
///
/// This test verifies:
/// 1. Contract selfdestructs during its constructor
/// 2. Contract is deleted (same-tx exception applies)
/// 3. No code or storage remains
/// 4. Since account never existed in DB before, execution state has no entry for it
#[tokio::test]
async fn test_selfdestruct_same_tx_post_dencun() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, wallet) = setup_node(EthereumHardfork::Cancun).await?;
    let mut account = wallet.account(0);
    let provider = node.rpc_provider();

    // Deploy contract that selfdestructs during its constructor
    let contract_address = account.next_contract_address();
    let deploy = account.deploy(selfdestruct_in_constructor_init_code()).await;
    let mined = node.mine([deploy]).await?.ensure_success()?;
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state: same-tx SELFDESTRUCT should destroy the account
    let account_state = execution_outcome.account(&contract_address);
    assert!(
        account_state.is_none(),
        "Post-Dencun same-tx: Account was created and selfdestructed in the same transaction, no trace in execution state"
    );

    // Verify via RPC that code and storage are cleared
    let code = provider.get_code_at(contract_address).await?;
    assert!(code.is_empty(), "Post-Dencun same-tx: Contract code should be deleted");

    let slot0 = provider.get_storage_at(contract_address, U256::ZERO).await?;
    assert_eq!(slot0, U256::ZERO, "Post-Dencun same-tx: Storage should be cleared");

    // Send ETH to the destroyed address in a new block to test cache behavior
    let transfer = account.transfer(contract_address, U256::from(1000)).await;
    node.mine([transfer]).await?.ensure_success()?;

    // Verify code is still empty and account received ETH
    let code_final = provider.get_code_at(contract_address).await?;
    assert!(code_final.is_empty(), "Post-Dencun same-tx: Contract code should remain deleted");

    let balance = provider.get_balance(contract_address).await?;
    assert_eq!(balance, U256::from(1000), "Post-Dencun same-tx: Account should have received ETH");

    Ok(())
}

/// Tests SELFDESTRUCT behavior pre-Dencun (Shanghai).
///
/// Pre-Dencun:
/// - SELFDESTRUCT deletes contract code and storage regardless of when contract was created
/// - The output state MUST mark the account as destroyed
///
/// This test verifies:
/// 1. Contract deploys with storage
/// 2. SELFDESTRUCT deletes code and storage
/// 3. Output state shows account IS destroyed
#[tokio::test]
async fn test_selfdestruct_pre_dencun() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, wallet) = setup_node(EthereumHardfork::Shanghai).await?;
    let mut account = wallet.account(0);
    let provider = node.rpc_provider();

    // Deploy contract that stores 0x42 at slot 0 and selfdestructs on any call
    let deploy = account.deploy(selfdestruct_contract_init_code()).await;
    let mined = node.mine([deploy]).await?.ensure_success()?;
    let contract_address =
        mined.receipts[0].contract_address.expect("Should have contract address");

    // Trigger SELFDESTRUCT by calling the contract
    let mined = node.mine([account.tx().to(contract_address).await]).await?.ensure_success()?;
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state: pre-Dencun, account MUST be destroyed
    let account_state = execution_outcome.account(&contract_address);
    assert!(
        matches!(account_state, Some(None)),
        "Pre-Dencun: Account MUST be marked as destroyed in output state"
    );

    // Verify via RPC that code and storage are cleared
    let code_after = provider.get_code_at(contract_address).await?;
    assert!(code_after.is_empty(), "Pre-Dencun: Contract code should be deleted");

    let slot0_after = provider.get_storage_at(contract_address, U256::ZERO).await?;
    assert_eq!(slot0_after, U256::ZERO, "Pre-Dencun: Storage should be cleared");

    // Send ETH to the destroyed contract address in a new block.
    // This tests cache behavior - the cache should correctly reflect the account was destroyed.
    // Pre-Dencun: the contract no longer exists, so this is just a plain ETH transfer.
    let transfer = account.transfer(contract_address, U256::from(1000)).await;
    let mined = node.mine([transfer]).await?.ensure_success()?;
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state shows the account exists (received ETH) but has no code
    let account_state = execution_outcome.account(&contract_address);
    // After receiving ETH, the account should exist with balance but no code
    assert!(
        matches!(account_state, Some(Some(_))),
        "Pre-Dencun: Account should exist after receiving ETH (even though contract was destroyed)"
    );

    // Verify code is still empty (contract was destroyed, only ETH was received)
    let code_final = provider.get_code_at(contract_address).await?;
    assert!(code_final.is_empty(), "Pre-Dencun: Contract code should remain deleted");

    // Verify storage is still cleared
    let slot0_final = provider.get_storage_at(contract_address, U256::ZERO).await?;
    assert_eq!(slot0_final, U256::ZERO, "Pre-Dencun: Storage should remain cleared");

    // Verify the account now has the ETH balance we sent
    let balance = provider.get_balance(contract_address).await?;
    assert_eq!(balance, U256::from(1000), "Pre-Dencun: Account should have received ETH");

    Ok(())
}

/// Tests that the engine persists the history of storage that a pre-Dencun SELFDESTRUCT wipes.
///
/// The contract sets slot 0 in its constructor. A later block self-destructs it without touching
/// slot 0. After the engine persists that block:
/// 1. The block's storage changeset holds the old value of slot 0.
/// 2. A historical read of slot 0 at the block below returns the old value. That read needs the
///    storage history index to list the block.
/// 3. No hashed storage row of the destroyed account is left behind.
///
/// The engine builds a block's hashed state in two ways: in the state root task, or from the
/// execution output when the task is off. Both must lead to the same history.
#[tokio::test]
async fn test_selfdestruct_pre_dencun_persists_wiped_storage_history() -> eyre::Result<()> {
    run_wiped_storage_history(false).await
}

/// Same as [`test_selfdestruct_pre_dencun_persists_wiped_storage_history`], with the state root
/// task off.
#[tokio::test]
async fn test_selfdestruct_pre_dencun_persists_wiped_storage_history_without_task(
) -> eyre::Result<()> {
    run_wiped_storage_history(true).await
}

async fn run_wiped_storage_history(state_root_fallback: bool) -> eyre::Result<()> {
    use alloy_eips::BlockNumberOrTag;
    use alloy_primitives::{keccak256, Address, B256};
    use reth_db::{cursor::DbCursorRO, tables, transaction::DbTx};
    use reth_e2e_test_utils::trie::assert_trie_consistency;
    use reth_provider::{DatabaseProviderFactory, StorageChangeSetReader};

    reth_tracing::init_test_tracing();

    let (mut node, wallet) = EthereumNode::test_setup_for(EthereumHardfork::Shanghai)
        .with_tree_config_modifier(move |config| {
            config
                .without_prewarming(true)
                .with_state_root_fallback(state_root_fallback)
                .with_num_state_masking_blocks(0)
                .with_persistence_threshold(0)
                .with_memory_block_buffer_target(0)
        })
        .build_single()
        .await?;
    let mut account = wallet.account(0);
    let provider = node.rpc_provider();

    // Deploy the contract, then persist it, so the wipe reads slot 0 from the database.
    let deploy = account.deploy(selfdestruct_contract_init_code()).await;
    let mined = node.mine([deploy]).await?.ensure_success()?;
    let contract = mined.receipts[0].contract_address.expect("Should have contract address");
    for _ in 0..2 {
        node.mine([account.transfer(Address::with_last_byte(1), U256::from(1)).await])
            .await?
            .ensure_success()?;
    }

    // Self-destruct without touching slot 0, then persist that block.
    let mined = node.mine([account.tx().to(contract).await]).await?.ensure_success()?;
    let destroyed_at = mined.block().number;
    for _ in 0..3 {
        node.mine([account.transfer(Address::with_last_byte(1), U256::from(1)).await])
            .await?
            .ensure_success()?;
    }
    node.wait_for_persisted_block(destroyed_at).await?;

    let db = node.inner.provider.database_provider_ro()?;
    let rows: Vec<_> = db
        .storage_changeset(destroyed_at)?
        .into_iter()
        .filter(|(key, _)| key.address() == contract)
        .map(|(_, entry)| (entry.key, entry.value))
        .collect();
    assert_eq!(
        rows,
        vec![(B256::ZERO, U256::from(0x42))],
        "the changeset of the destroying block must restore slot 0"
    );

    let before = provider
        .get_storage_at(contract, U256::ZERO)
        .block_id(BlockNumberOrTag::Number(destroyed_at - 1).into())
        .await?;
    assert_eq!(before, U256::from(0x42), "a historical read must return the wiped value");

    let mut hashed = db.tx_ref().cursor_dup_read::<tables::HashedStorages>()?;
    assert!(
        hashed.seek_exact(keccak256(contract))?.is_none(),
        "no hashed storage of the destroyed account may remain"
    );

    assert_trie_consistency(&node.inner.provider)?;
    Ok(())
}

/// Tests SELFDESTRUCT in same transaction as creation, where account previously had ETH
/// (post-Dencun).
///
/// Post-Dencun (EIP-6780):
/// - The same-tx exception applies when the CONTRACT is created in that transaction
/// - Even if the address previously had ETH (as an EOA), deploying a contract there and
///   selfdestructing in the same tx DOES delete the contract
/// - The "created in same tx" refers to contract creation, not account existence
///
/// This test verifies:
/// 1. Send ETH to the future contract address (address has balance but no code)
/// 2. Deploy contract that selfdestructs during constructor to that address
/// 3. Contract is deleted (same-tx exception applies - contract was created this tx)
/// 4. Code and storage are cleared
/// 5. Since account existed in DB before (had ETH), execution state marks it as Destroyed
#[tokio::test]
async fn test_selfdestruct_same_tx_preexisting_account_post_dencun() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (mut node, wallet) = setup_node(EthereumHardfork::Cancun).await?;
    let mut account = wallet.account(0);
    let provider = node.rpc_provider();

    // Calculate where the contract will be deployed (CREATE uses sender + nonce)
    // We'll use the next nonce for deployment, so first send ETH with the current one.
    let future_contract_address = account.address().create(account.nonce() + 1);

    // Send ETH to the future contract address first (makes it a pre-existing account)
    let transfer = account.transfer(future_contract_address, U256::from(1000)).await;
    node.mine([transfer]).await?.ensure_success()?;

    // Verify the account exists and has balance
    let balance_before = provider.get_balance(future_contract_address).await?;
    assert_eq!(balance_before, U256::from(1000), "Account should have ETH before deployment");

    // Now deploy contract that selfdestructs during its constructor to the same address
    let deploy = account.deploy(selfdestruct_in_constructor_init_code()).await;
    let mined = node.mine([deploy]).await?.ensure_success()?;

    // Verify deployment went to the expected address
    assert_eq!(
        mined.receipts[0].contract_address,
        Some(future_contract_address),
        "Contract should be deployed to pre-computed address"
    );
    let execution_outcome = mined.chain.execution_outcome();

    // Verify the output state: same-tx exception DOES apply because contract was created this tx
    // The account should be marked as destroyed. Since it had prior state (ETH balance),
    // the execution state will contain it with status Destroyed and original_info set.
    let account_state = execution_outcome.account(&future_contract_address);
    assert!(
        matches!(account_state, Some(None)),
        "Post-Dencun same-tx with prior ETH: Account MUST be marked as destroyed"
    );

    // Verify via RPC that code and storage are cleared
    let code = provider.get_code_at(future_contract_address).await?;
    assert!(code.is_empty(), "Post-Dencun same-tx: Contract code should be deleted");

    let slot0 = provider.get_storage_at(future_contract_address, U256::ZERO).await?;
    assert_eq!(slot0, U256::ZERO, "Post-Dencun same-tx: Storage should be cleared");

    // Balance should be zero (sent to beneficiary during SELFDESTRUCT)
    let balance_after = provider.get_balance(future_contract_address).await?;
    assert_eq!(
        balance_after,
        U256::ZERO,
        "Post-Dencun same-tx: Balance should be zero (sent to beneficiary)"
    );

    // Send ETH to the destroyed address to verify cache behavior
    let transfer = account.transfer(future_contract_address, U256::from(2000)).await;
    node.mine([transfer]).await?.ensure_success()?;

    // Verify the account received ETH and has no code (it's now just an EOA)
    let balance_final = provider.get_balance(future_contract_address).await?;
    assert_eq!(balance_final, U256::from(2000), "Account should have received ETH");

    let code_final = provider.get_code_at(future_contract_address).await?;
    assert!(code_final.is_empty(), "Code should remain empty after ETH transfer");

    let slot0_final = provider.get_storage_at(future_contract_address, U256::ZERO).await?;
    assert_eq!(slot0_final, U256::ZERO, "Storage should remain cleared");

    Ok(())
}
