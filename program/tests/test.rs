use anchor_lang::AccountDeserialize;
use std::{fs::File, io::Read};
use timelock_program_authority::accounts;
use timelock_program_authority::get_deployment_address;
use timelock_program_authority::get_immutable_deployment_address;
use timelock_program_authority::get_timelock_address;
use timelock_program_authority::instruction;
use timelock_program_authority::TimelockAuthority;

use anchor_lang::{
    prelude::{Pubkey, Rent},
    system_program, InstructionData, ToAccountMetas,
};
use solana_program_test::*;

use solana_sdk::{
    bpf_loader_upgradeable,
    instruction::Instruction,
    message::Message,
    packet::PACKET_DATA_SIZE,
    signature::{Keypair, Signature},
    signer::Signer,
    sysvar,
    transaction::Transaction,
};

pub fn timelock_test() -> ProgramTest {
    ProgramTest::new(
        "timelock_program_authority",
        timelock_program_authority::id(),
        None,
    )
}

pub fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::from_bytes(&keypair.to_bytes()).unwrap()
}

fn read_elf(program_location: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(program_location)
        .map_err(|err| format!("Unable to open program file {}: {}", program_location, err))?;
    let mut program_data = Vec::new();
    file.read_to_end(&mut program_data)
        .map_err(|err| format!("Unable to open program file {}: {}", program_location, err))?;
    // Skip verification of the program for testing
    Ok(program_data)
}

fn calculate_max_chunk_size<F>(create_msg: &F) -> usize
where
    F: Fn(u32, Vec<u8>) -> Message,
{
    let baseline_msg = create_msg(0, Vec::new());
    let tx_size = bincode::serialized_size(&Transaction {
        signatures: vec![
            Signature::default();
            baseline_msg.header.num_required_signatures as usize
        ],
        message: baseline_msg,
    })
    .unwrap() as usize;
    // add 1 byte buffer to account for shortvec encoding
    PACKET_DATA_SIZE.saturating_sub(tx_size).saturating_sub(1)
}

async fn write_to_buffer(
    ctx: &mut ProgramTestContext,
    buffer: &Keypair,
    program_data: &[u8],
) -> Result<(), BanksClientError> {
    let minimum_balance = Rent::default().minimum_balance(program_data.len() * 2);
    let buffer_pubkey = buffer.pubkey();

    let create_instructions = bpf_loader_upgradeable::create_buffer(
        &ctx.payer.pubkey(),
        &buffer_pubkey,
        &ctx.payer.pubkey(),
        minimum_balance,
        program_data.len(),
    )
    .unwrap();

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let create_msg = |offset: u32, bytes: Vec<u8>| {
        let instruction =
            bpf_loader_upgradeable::write(&buffer_pubkey, &ctx.payer.pubkey(), offset, bytes);
        Message::new_with_blockhash(&[instruction], Some(&ctx.payer.pubkey()), &blockhash)
    };
    let chunk_size = calculate_max_chunk_size(&create_msg);

    let create_write_ix = |offset: u32, bytes: Vec<u8>| {
        bpf_loader_upgradeable::write(&buffer_pubkey, &ctx.payer.pubkey(), offset, bytes)
    };

    let mut write_instructions = vec![];
    for (chunk, i) in program_data.chunks(chunk_size).zip(0..) {
        write_instructions.push(create_write_ix((i * chunk_size) as u32, chunk.to_vec()));
    }
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &create_instructions,
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, &buffer],
            blockhash,
        ))
        .await
        .unwrap();

    for ix in write_instructions {
        let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
        ctx.banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[ix],
                Some(&ctx.payer.pubkey()),
                &[&ctx.payer],
                blockhash,
            ))
            .await?;
    }

    println!(
        "Finished writing program to buffer account: {:?}",
        buffer_pubkey
    );
    Ok(())
}

async fn deploy_program(
    ctx: &mut ProgramTestContext,
    program_data: Vec<u8>,
    program_id: &Keypair,
) -> Result<(), BanksClientError> {
    let buffer = Keypair::new();
    write_to_buffer(ctx, &buffer, &program_data).await?;
    let minimum_balance = Rent::default().minimum_balance(program_data.len() * 2);
    let upgrade = &bpf_loader_upgradeable::deploy_with_max_program_len(
        &ctx.payer.pubkey(),
        &program_id.pubkey(),
        &buffer.pubkey(),
        &ctx.payer.pubkey(),
        minimum_balance,
        program_data.len(),
    )
    .unwrap();

    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            upgrade,
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, &program_id],
            blockhash,
        ))
        .await
}

async fn initialize_timelock_authority(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    timelock_in_slots: u64,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = Pubkey::find_program_address(
        &[b"timelock-authority".as_ref(), program_id.as_ref()],
        &timelock_program_authority::id(),
    )
    .0;

    let initialize_timelock = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::InitializeTimelock {
            timelock,
            program: *program_id,
            program_data: Pubkey::find_program_address(
                &[program_id.as_ref()],
                &bpf_loader_upgradeable::id(),
            )
            .0,
            program_authority: ctx.payer.pubkey(),
            payer: ctx.payer.pubkey(),
            rent: sysvar::rent::id(),
            system_program: system_program::ID,
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::InitializeAndAssignTimelockAuthority { timelock_in_slots }.data(),
    };

    println!("Initialize timelock: {:?}", initialize_timelock);

    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[initialize_timelock],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer],
            blockhash,
        ))
        .await
}

async fn initialize_timelock_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    buffer: &Pubkey,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let initialize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::InitializeProgramUpgrade {
            program: *program_id,
            buffer: *buffer,
            authority: authority.pubkey(),
            payer: ctx.payer.pubkey(),
            timelock,
            deployment: get_deployment_address(program_id, buffer, &ctx.payer.pubkey()),
            rent: sysvar::rent::id(),
            system_program: system_program::ID,
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::InitializeProgramUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[initialize_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, &authority],
            blockhash,
        ))
        .await
}

async fn cancel_timelock_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    buffer: &Pubkey,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let cancel_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::CancelProgramUpgrade {
            buffer: *buffer,
            payer: ctx.payer.pubkey(),
            timelock,
            deployment: get_deployment_address(program_id, buffer, &ctx.payer.pubkey()),
            authority: authority.pubkey(),
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::CancelProgramUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[cancel_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, &authority],
            blockhash,
        ))
        .await
}

async fn finalize_timelock_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    buffer: &Pubkey,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let finalize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::FinalizeProgramUpgrade {
            program: *program_id,
            program_data: Pubkey::find_program_address(
                &[program_id.as_ref()],
                &bpf_loader_upgradeable::id(),
            )
            .0,
            buffer: *buffer,
            payer: ctx.payer.pubkey(),
            timelock,
            deployment: get_deployment_address(program_id, buffer, &ctx.payer.pubkey()),
            rent: sysvar::rent::id(),
            clock: sysvar::clock::id(),
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::FinalizeProgramUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[finalize_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer],
            blockhash,
        ))
        .await
}

async fn initialize_immutable_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let initialize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::InitializeImmutableUpgrade {
            payer: ctx.payer.pubkey(),
            authority: authority.pubkey(),
            timelock,
            deployment: get_immutable_deployment_address(program_id),
            rent: sysvar::rent::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::InitializeImmutableUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[initialize_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, authority],
            blockhash,
        ))
        .await
}

async fn cancel_immutable_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let cancel_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::CancelImmutableUpgrade {
            payer: ctx.payer.pubkey(),
            authority: authority.pubkey(),
            timelock,
            deployment: get_immutable_deployment_address(program_id),
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::CancelImmutableUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[cancel_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer, authority],
            blockhash,
        ))
        .await
}

async fn finalize_immutable_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let timelock = get_timelock_address(program_id);
    let finalize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::FinalizeImmutableUpgrade {
            program: *program_id,
            program_data: Pubkey::find_program_address(
                &[program_id.as_ref()],
                &bpf_loader_upgradeable::id(),
            )
            .0,
            payer: ctx.payer.pubkey(),
            authority: *authority,
            timelock,
            deployment: get_immutable_deployment_address(program_id),
            bpf_loader_upgradeable_program: bpf_loader_upgradeable::id(),
        }
        .to_account_metas(None),
        data: instruction::FinalizeImmutableUpgrade {}.data(),
    };
    ctx.banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[finalize_upgrade],
            Some(&ctx.payer.pubkey()),
            &[&ctx.payer],
            blockhash,
        ))
        .await
}

async fn test_initialize_timelock_authority_and_attempt_to_change_authority(
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

async fn test_finalize_timelock_upgrade(
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
        .active_deployment
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
        .active_deployment
            == None,
        "Deployment account is removed after upgrade"
    );
    Ok(())
}

async fn test_cancel_timelock_upgrade(ctx: &mut ProgramTestContext, program_id: &Pubkey) {
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
        .active_deployment
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
        .active_deployment
            == None,
        "Deployment account is removed after cancel"
    );
}

async fn test_cancel_immutable_upgrade(ctx: &mut ProgramTestContext, program_id: &Pubkey) {
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

async fn test_finalize_immutable_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    slots: u64,
) {
    let payer = clone_keypair(&ctx.payer);
    let buffer = Keypair::new();
    let program_data = read_elf(find_file("bar.so").unwrap().to_str().unwrap()).unwrap();
    write_to_buffer(ctx, &buffer, &program_data).await.unwrap();
    initialize_immutable_upgrade(ctx, &program_id, &payer)
        .await
        .unwrap();

    // Validate that you cannot immediately upgrade the program
    assert!(
        finalize_immutable_upgrade(ctx, &program_id, &payer.pubkey())
            .await
            .is_err(),
        "Cannot finalize immutable upgrade before timelock expires"
    );

    let slot = ctx.banks_client.get_root_slot().await.unwrap();
    ctx.warp_to_slot(slot + slots).unwrap();
    assert!(
        finalize_immutable_upgrade(ctx, &program_id, &payer.pubkey())
            .await
            .is_ok(),
        "Can permissionlessly finalize immutable upgrade after timelock expires"
    );

    assert!(
        ctx.banks_client
            .get_account(get_timelock_address(&program_id))
            .await
            .unwrap()
            .is_none(),
        "Timelock is destroyed after upgrade"
    );
    assert!(
        ctx.banks_client
            .get_account(get_immutable_deployment_address(&program_id))
            .await
            .unwrap()
            .is_none(),
        "Immutable deployment address is destroyed after upgrade"
    );
}

#[tokio::test]
async fn test_end_to_end_program_upgrade() {
    let mut ctx = timelock_test().start_with_context().await;
    let foo_program = find_file("foo.so").unwrap();
    let foo_program_id = Keypair::new();
    let program_id = foo_program_id.pubkey();
    let program_data = read_elf(foo_program.to_str().unwrap()).unwrap();
    let slots = 216_000;

    // Deploy the original Foo program
    deploy_program(&mut ctx, program_data, &foo_program_id)
        .await
        .unwrap();

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

    // Test canceling an immutable upgrade
    test_cancel_immutable_upgrade(&mut ctx, &program_id).await;

    // Test finalizing an immutable upgrade
    test_finalize_immutable_upgrade(&mut ctx, &program_id, slots).await;
}
