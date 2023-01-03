use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    bpf_loader_upgradeable,
    program::{invoke, invoke_signed},
};

use crate::{BpfLoaderUpgradeable, Deployment, TimelockAuthority, TimelockError};

#[derive(Accounts)]
pub struct InitializeProgramUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = authority,
        constraint = timelock.active_upgrade == None,
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        init,
        payer = payer,
        seeds = [
            b"timelock-deployment".as_ref(),
            timelock.key().as_ref(),
            payer.key().as_ref(),
            buffer.key().as_ref(),
        ],
        bump,
        space = 8 + 8 + 32 + 32
    )]
    pub deployment: Account<'info, Deployment>,
    #[account(mut)]
    /// CHECK:
    pub buffer: UncheckedAccount<'info>,
    /// CHECK:
    pub program: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn initialize_program_upgrade(ctx: Context<InitializeProgramUpgrade>) -> Result<()> {
    let InitializeProgramUpgrade {
        timelock,
        deployment,
        buffer,
        authority,
        payer,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    // First change the authority of the buffer to the timelock authority
    invoke(
        &bpf_loader_upgradeable::set_buffer_authority(
            &buffer.key(),
            &authority.key(),
            &timelock.key(),
        ),
        &[
            buffer.to_account_info(),
            authority.to_account_info(),
            timelock.to_account_info(),
            bpf_loader_upgradeable_program.to_account_info(),
        ],
    )?;

    let clock = Clock::get()?;
    **deployment = Deployment {
        initialization_slot: clock.slot,
        payer: payer.key(),
        buffer: buffer.key(),
    };
    // Then update the timelock authority to reflect the upgrade in progress
    timelock.active_upgrade = Some(deployment.key());
    Ok(())
}

#[derive(Accounts)]
pub struct CancelProgramUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
            ],
            bump,
            has_one = authority,
            constraint = timelock.active_upgrade == Some(deployment.key()),
        )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
            mut,
        close = payer,
        seeds = [
            b"timelock-deployment".as_ref(),
            timelock.key().as_ref(),
            payer.key().as_ref(),
            buffer.key().as_ref(),
            ],
            bump,
            has_one = payer,
        )]
    pub deployment: Account<'info, Deployment>,
    /// CHECK:
    #[account(mut)]
    pub buffer: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn cancel_program_upgrade(ctx: Context<CancelProgramUpgrade>) -> Result<()> {
    let CancelProgramUpgrade {
        timelock,
        buffer,
        payer,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    // Close the buffer and return the funds to the payer
    invoke_signed(
        &bpf_loader_upgradeable::close(&buffer.key(), &payer.key(), &timelock.key()),
        &[
            buffer.to_account_info(),
            payer.to_account_info(),
            timelock.to_account_info(),
            bpf_loader_upgradeable_program.to_account_info(),
        ],
        &[&[
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
            &[ctx.bumps["timelock"]],
        ]],
    )?;
    // Then mark the deployment as inactive
    timelock.active_upgrade = None;
    Ok(())
}

#[derive(Accounts)]
pub struct FinalizeProgramUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        constraint = timelock.active_upgrade == Some(deployment.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"timelock-deployment".as_ref(),
            timelock.key().as_ref(),
            payer.key().as_ref(),
            buffer.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub deployment: Account<'info, Deployment>,
    /// CHECK:
    #[account(mut)]
    pub program: UncheckedAccount<'info>,
    /// CHECK:
    #[account(mut)]
    pub program_data: UncheckedAccount<'info>,
    /// CHECK:
    #[account(mut)]
    pub buffer: UncheckedAccount<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn finalize_program_upgrade(ctx: Context<FinalizeProgramUpgrade>) -> Result<()> {
    let FinalizeProgramUpgrade {
        timelock,
        deployment,
        program,
        program_data,
        buffer,
        payer,
        rent,
        clock,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    // Verify that the timelock has expired
    let curr_slot = Clock::get()?.slot;
    msg!("Timelock start slot: {}", deployment.initialization_slot);
    msg!("Current slot: {}", curr_slot);
    msg!(
        "Slots until expiration: {}",
        timelock
            .timelock_duration_in_slots
            .saturating_sub(curr_slot.saturating_sub(deployment.initialization_slot))
    );
    require!(
        curr_slot - deployment.initialization_slot >= timelock.timelock_duration_in_slots,
        TimelockError::TimelockNotExpired
    );
    // Upgrade the program
    invoke_signed(
        &bpf_loader_upgradeable::upgrade(
            &program.key(),
            &buffer.key(),
            &timelock.key(),
            &payer.key(),
        ),
        &[
            program_data.to_account_info(),
            buffer.to_account_info(),
            timelock.to_account_info(),
            payer.to_account_info(),
            rent.to_account_info(),
            clock.to_account_info(),
            bpf_loader_upgradeable_program.to_account_info(),
        ],
        &[&[
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
            &[ctx.bumps["timelock"]],
        ]],
    )?;
    // Then mark the deployment as inactive
    timelock.active_upgrade = None;
    Ok(())
}
