use anchor_lang::{prelude::Pubkey, AccountDeserialize};
use solana_program_test::{find_file, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    bpf_loader_upgradeable, signature::Keypair, signer::Signer, transaction::Transaction,
};

pub mod transactions;
pub mod utils;

use timelock_program_authority::{
    get_deployment_address, get_immutable_upgrade_address,
    get_modify_timelock_duration_upgrade_address, get_timelock_address, TimelockAuthority,
};
pub use transactions::*;
pub use utils::*;

pub fn timelock_test() -> ProgramTest {
    ProgramTest::new(
        "timelock_program_authority",
        timelock_program_authority::id(),
        None,
    )
}

#[tokio::test]
async fn test_end_to_end_program_upgrade() {
    let mut ctx = timelock_test().start_with_context().await;
    let foo_program = find_file("foo.so").unwrap();
    let foo_program_id = Keypair::new();
    let program_id = foo_program_id.pubkey();
    let program_data = read_elf(foo_program.to_str().unwrap()).unwrap();
    let mut slots = 108_000;

    // Deploy the original Foo program
    deploy_program(&mut ctx, program_data, &foo_program_id)
        .await
        .unwrap();

    // Make sure you cannot call cancel or finalize on a non-existent upgrade
    test_assert_cannot_cancel_or_finalize_non_existent_upgrade(&mut ctx, &program_id).await;

    // Upgrade the program authority to the timelock program and verify that the
    // the authority cannot be changed by the payer
    assert!(
        test_initialize_timelock_authority_and_attempt_to_change_authority(
            &mut ctx,
            &program_id,
            slots
        )
        .await
        .is_err(),
        "Cannot change program authority after it has been delegated to the timelock"
    );

    // Test finalizing a timelock upgrade
    test_finalize_timelock_upgrade(&mut ctx, &program_id, slots)
        .await
        .unwrap();

    // Test canceling an upgrade
    test_cancel_timelock_upgrade(&mut ctx, &program_id).await;

    // Check that the cancel modify timelock works
    test_cancel_modify_timelock_duration(&mut ctx, &program_id, slots, slots * 2).await;

    // Check that the finalize modify timelock works
    test_modify_timelock_duration(&mut ctx, &program_id, slots, slots * 2).await;

    // Test that you can't finalize an upgrade when the duration doesn't pass
    assert!(
        test_finalize_immutable_upgrade(&mut ctx, &program_id, slots)
            .await
            .is_err(),
        "Cannot finalize an upgrade that has already been finalized"
    );
    let payer = clone_keypair(&ctx.payer);
    cancel_immutable_upgrade(&mut ctx, &program_id, &payer)
        .await
        .unwrap();

    // Test canceling an immutable upgrade
    test_cancel_immutable_upgrade(&mut ctx, &program_id).await;

    // Test that you can update when you double the duration now
    slots *= 2;
    // Test finalizing an immutable upgrade
    test_finalize_immutable_upgrade(&mut ctx, &program_id, slots)
        .await
        .unwrap();
}

// Helper functions

pub async fn test_initialize_timelock_authority_and_attempt_to_change_authority(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
) -> Result<(), BanksClientError> {
    // Initialize the timelock authority on the Foo program
    initialize_timelock_authority(ctx, program_id, slots) // Around 1 day
        .await
        .unwrap();

    // Validate that you can no longer change the program authority with the payer
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let random_key = Pubkey::new_unique();
    let transfer_program_authority = bpf_loader_upgradeable::set_upgrade_authority(
        program_id,
        &ctx.payer.pubkey(),
        Some(&random_key),
    );
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[transfer_program_authority],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer],
            blockhash,
        ))
        .await
}

pub async fn test_finalize_timelock_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
) -> Result<(), BanksClientError> {
    // Initialize timelock upgrade
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    let program_data = read_elf(find_file("bar.so").unwrap().to_str().unwrap()).unwrap();
    write_to_buffer(ctx, &buffer, &program_data).await?;
    initialize_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer).await?;

    assert!(
        TimelockAuthority::try_deserialize(
            &mut ctx
                .banks_client
                .get_account(get_timelock_address(&program_id))
                .await
                .unwrap()
                .unwrap()
                .data
                .as_slice()
        )
        .unwrap()
        .active_upgrade
            == Some(get_deployment_address(
                &program_id,
                &buffer.pubkey(),
                &payer.pubkey()
            )),
        "Deployment account is set after initialize"
    );

    // Validate that you cannot immediately upgrade the program
    assert!(
        finalize_timelock_upgrade(ctx, &program_id, &buffer.pubkey())
            .await
            .is_err(),
        "Cannot finalize upgrade before timelock expires"
    );

    // Warp the slot to the timelock expiration
    let slot = ctx.banks_client.get_root_slot().await?;
    ctx.warp_to_slot(slot + slots).unwrap();
    assert!(
        finalize_timelock_upgrade(ctx, &program_id, &buffer.pubkey())
            .await
            .is_ok(),
        "Can permissionlessly finalize upgrade after timelock expires"
    );

    assert!(
        ctx.banks_client
            .get_account(get_deployment_address(
                &program_id,
                &buffer.pubkey(),
                &payer.pubkey()
            ))
            .await
            .unwrap()
            .is_none(),
        "Deployment account is removed after upgrade"
    );

    assert!(
        TimelockAuthority::try_deserialize(
            &mut ctx
                .banks_client
                .get_account(get_timelock_address(&program_id))
                .await
                .unwrap()
                .unwrap()
                .data
                .as_slice()
        )
        .unwrap()
        .active_upgrade
            == None,
        "Deployment account is removed after upgrade"
    );
    Ok(())
}

pub async fn test_cancel_timelock_upgrade(ctx: &mut ProgramTestContext, program_id: &Pubkey) {
    // Initialize timelock upgrade
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    let program_data = read_elf(find_file("bar.so").unwrap().to_str().unwrap()).unwrap();
    write_to_buffer(ctx, &buffer, &program_data).await.unwrap();
    initialize_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
        .await
        .unwrap();

    assert!(
        TimelockAuthority::try_deserialize(
            &mut ctx
                .banks_client
                .get_account(get_timelock_address(&program_id))
                .await
                .unwrap()
                .unwrap()
                .data
                .as_slice()
        )
        .unwrap()
        .active_upgrade
            == Some(get_deployment_address(
                &program_id,
                &buffer.pubkey(),
                &payer.pubkey()
            )),
        "Deployment account is set after initialize"
    );

    // Warp to a new slot to avoid dups
    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + 1).unwrap();

    assert!(
        initialize_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
            .await
            .is_err()
    );
    assert!(initialize_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .is_err());
    assert!(cancel_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .is_err());
    assert!(
        finalize_immutable_upgrade(ctx, &program_id, &payer.pubkey())
            .await
            .is_err()
    );

    // Cancel the upgrade
    cancel_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
        .await
        .unwrap();

    assert!(
        TimelockAuthority::try_deserialize(
            &mut ctx
                .banks_client
                .get_account(get_timelock_address(&program_id))
                .await
                .unwrap()
                .unwrap()
                .data
                .as_slice()
        )
        .unwrap()
        .active_upgrade
            == None,
        "Deployment account is removed after cancel"
    );
}

pub async fn test_cancel_immutable_upgrade(ctx: &mut ProgramTestContext, program_id: &Pubkey) {
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    let program_data = read_elf(find_file("bar.so").unwrap().to_str().unwrap()).unwrap();
    write_to_buffer(ctx, &buffer, &program_data).await.unwrap();
    initialize_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .unwrap();

    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + 1).unwrap();

    assert!(initialize_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .is_err());
    assert!(
        initialize_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
            .await
            .is_err()
    );
    assert!(
        cancel_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
            .await
            .is_err()
    );
    assert!(
        finalize_timelock_upgrade(ctx, &program_id, &buffer.pubkey(),)
            .await
            .is_err()
    );
    // Cancel the immutable upgrade
    cancel_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .unwrap();
}

pub async fn test_finalize_immutable_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
) -> Result<(), BanksClientError> {
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    let program_data = read_elf(find_file("bar.so").unwrap().to_str().unwrap()).unwrap();
    write_to_buffer(ctx, &buffer, &program_data).await?;
    initialize_immutable_upgrade(ctx, &program_id, &payer).await?;

    // Validate that you cannot immediately upgrade the program
    assert!(
        finalize_immutable_upgrade(ctx, &program_id, &payer.pubkey())
            .await
            .is_err(),
        "Cannot finalize immutable upgrade before timelock expires"
    );

    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + slots).unwrap();
    finalize_immutable_upgrade(ctx, &program_id, &payer.pubkey()).await?;

    assert!(
        ctx.banks_client
            .get_account(get_timelock_address(&program_id))
            .await?
            .is_none(),
        "Timelock is destroyed after upgrade"
    );
    assert!(
        ctx.banks_client
            .get_account(get_immutable_upgrade_address(&program_id))
            .await?
            .is_none(),
        "Immutable deployment address is destroyed after upgrade"
    );
    Ok(())
}

pub async fn test_assert_cannot_cancel_or_finalize_non_existent_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
) {
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    assert!(
        cancel_timelock_upgrade(ctx, &program_id, &buffer.pubkey(), &payer)
            .await
            .is_err(),
        "Cannot cancel a non-existent upgrade"
    );

    assert!(
        finalize_timelock_upgrade(ctx, &program_id, &buffer.pubkey())
            .await
            .is_err(),
        "Cannot finalize a non-existent upgrade"
    );

    assert!(
        cancel_immutable_upgrade(ctx, &program_id, &payer)
            .await
            .is_err(),
        "Cannot cancel a non-existent upgrade"
    );

    assert!(
        finalize_immutable_upgrade(ctx, &program_id, &buffer.pubkey())
            .await
            .is_err(),
        "Cannot finalize a non-existent upgrade"
    );

    assert!(
        cancel_modify_timelock_duration(ctx, &program_id, &payer)
            .await
            .is_err(),
        "Cannot cancel a non-existent upgrade"
    );

    assert!(
        finalize_modify_timelock_duration(ctx, &program_id)
            .await
            .is_err(),
        "Cannot finalize a non-existent upgrade"
    );
}

async fn test_modify_timelock_duration(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
    duration_in_slots: u64,
) {
    let payer = clone_keypair(&ctx.payer);
    initialize_modify_timelock_duration_upgrade(ctx, &program_id, &payer, duration_in_slots)
        .await
        .unwrap();

    // Validate that you cannot immediately upgrade the program
    assert!(
        finalize_modify_timelock_duration(ctx, &program_id)
            .await
            .is_err(),
        "Cannot finalize timelock duration upgrade before timelock expires"
    );

    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + slots).unwrap();
    assert!(
        finalize_modify_timelock_duration(ctx, &program_id)
            .await
            .is_ok(),
        "Can permissionlessly finalize timelock duration upgrade after timelock expires"
    );

    assert!(
        ctx.banks_client
            .get_account(get_modify_timelock_duration_upgrade_address(&program_id))
            .await
            .unwrap()
            .is_none(),
        "Timelock upgrade is destroyed after upgrade"
    );
    assert!(
        TimelockAuthority::try_deserialize(
            &mut ctx
                .banks_client
                .get_account(get_timelock_address(&program_id))
                .await
                .unwrap()
                .unwrap()
                .data
                .as_slice()
        )
        .unwrap()
        .timelock_duration_in_slots
            == duration_in_slots,
        "Timelock duration is updated after upgrade"
    );
}

async fn test_cancel_modify_timelock_duration(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
    duration_in_slots: u64,
) {
    let payer = clone_keypair(&ctx.payer);
    initialize_modify_timelock_duration_upgrade(ctx, &program_id, &payer, duration_in_slots)
        .await
        .unwrap();

    // Validate that you cannot immediately upgrade the program
    assert!(
        finalize_modify_timelock_duration(ctx, &program_id)
            .await
            .is_err(),
        "Cannot finalize timelock duration upgrade before timelock expires"
    );

    let timelock = TimelockAuthority::try_deserialize(
        &mut ctx
            .banks_client
            .get_account(get_timelock_address(&program_id))
            .await
            .unwrap()
            .unwrap()
            .data
            .as_slice(),
    )
    .unwrap();
    assert!(
        timelock.active_upgrade == Some(get_modify_timelock_duration_upgrade_address(&program_id)),
        "Upgrade key does not match"
    );

    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + slots).unwrap();

    assert!(
        cancel_modify_timelock_duration(ctx, &program_id, &payer)
            .await
            .is_ok(),
        "Can cancel timelock duration upgrade after timelock expires"
    );
    assert!(
        ctx.banks_client
            .get_account(get_modify_timelock_duration_upgrade_address(&program_id))
            .await
            .unwrap()
            .is_none(),
        "Timelock upgrade is destroyed after upgrade"
    );
    let timelock = TimelockAuthority::try_deserialize(
        &mut ctx
            .banks_client
            .get_account(get_timelock_address(&program_id))
            .await
            .unwrap()
            .unwrap()
            .data
            .as_slice(),
    )
    .unwrap();
    assert!(
        timelock.timelock_duration_in_slots == slots,
        "Timelock duration is unchanged"
    );
    assert!(
        timelock.active_upgrade == None,
        "Upgrade key should be None"
    );
}
