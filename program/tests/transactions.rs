use solana_sdk::packet::PACKET_DATA_SIZE;
use solana_sdk::signature::Signature;
use timelock_program_authority::accounts;
use timelock_program_authority::get_deployment_address;
use timelock_program_authority::get_immutable_upgrade_address;
use timelock_program_authority::get_modify_timelock_duration_upgrade_address;
use timelock_program_authority::get_timelock_address;
use timelock_program_authority::instruction;

use anchor_lang::{
    prelude::{Pubkey, Rent},
    system_program, InstructionData, ToAccountMetas,
};
use solana_program_test::*;

use solana_sdk::{
    bpf_loader_upgradeable, instruction::Instruction, message::Message, signature::Keypair,
    signer::Signer, sysvar, transaction::Transaction,
};

pub fn calculate_max_chunk_size<F>(create_msg: &F) -> usize
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

pub async fn write_to_buffer(
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

pub async fn deploy_program(
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

pub async fn initialize_timelock_authority(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    timelock_duration_in_slots: u64,
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
        data: instruction::InitializeAndAssignTimelockAuthority {
            timelock_duration_in_slots,
        }
        .data(),
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

pub async fn initialize_timelock_upgrade(
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

pub async fn cancel_timelock_upgrade(
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

pub async fn finalize_timelock_upgrade(
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

pub async fn initialize_immutable_upgrade(
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
            immutable_upgrade: get_immutable_upgrade_address(program_id),
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

pub async fn cancel_immutable_upgrade(
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
            immutable_upgrade: get_immutable_upgrade_address(program_id),
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

pub async fn finalize_immutable_upgrade(
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
            immutable_upgrade: get_immutable_upgrade_address(program_id),
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

pub async fn initialize_modify_timelock_duration_upgrade(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Keypair,
    new_timelock_duration_in_slots: u64,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();

    let timelock = get_timelock_address(program_id);
    let initialize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::InitializeModifyTimelockDuration {
            payer: ctx.payer.pubkey(),
            authority: authority.pubkey(),
            timelock,
            modify_duration_upgrade: get_modify_timelock_duration_upgrade_address(program_id),
            rent: sysvar::rent::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::InitializeModifyTimelockDuration {
            new_timelock_duration_in_slots,
        }
        .data(),
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

pub async fn cancel_modify_timelock_duration(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let timelock = get_timelock_address(program_id);
    let cancel_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::CancelModifyTimelockDuration {
            payer: ctx.payer.pubkey(),
            authority: authority.pubkey(),
            timelock,
            modify_duration_upgrade: get_modify_timelock_duration_upgrade_address(program_id),
        }
        .to_account_metas(None),
        data: instruction::CancelModifyTimelockDuration {}.data(),
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

pub async fn finalize_modify_timelock_duration(
    ctx: &mut ProgramTestContext,
    program_id: &Pubkey,
    authority: &Pubkey,
) -> Result<(), BanksClientError> {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let timelock = get_timelock_address(program_id);
    let finalize_upgrade = Instruction {
        program_id: timelock_program_authority::id(),
        accounts: accounts::FinalizeModifyTimelockDuration {
            payer: ctx.payer.pubkey(),
            authority: *authority,
            timelock,
            modify_duration_upgrade: get_modify_timelock_duration_upgrade_address(program_id),
        }
        .to_account_metas(None),
        data: instruction::FinalizeModifyTimelockDuration {}.data(),
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
