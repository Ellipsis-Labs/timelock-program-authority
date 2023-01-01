use anchor_lang::prelude::*;
use anchor_lang::solana_program::{bpf_loader_upgradeable, program::invoke_signed};

use crate::{BpfLoaderUpgradeable, Deployment, TimelockAuthority, TimelockError};

#[derive(Accounts)]
pub struct InitializeImmutableUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = authority,
        constraint = timelock.active_deployment == None,
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        init,
        payer = payer,
        seeds = [
            b"immutable".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        space = 8 + 8 + 32 + 32
    )]
    pub deployment: Account<'info, Deployment>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_immutable_upgrade(ctx: Context<InitializeImmutableUpgrade>) -> Result<()> {
    let InitializeImmutableUpgrade {
        timelock,
        deployment,
        payer,
        ..
    } = ctx.accounts;
    let clock = Clock::get()?;
    // Create a dummy deployment to start the countdown
    **deployment = Deployment {
        slot: clock.slot,
        payer: payer.key(),
        buffer: anchor_lang::system_program::ID,
    };
    // Then update the timelock authority to reflect the upgrade in progress
    timelock.active_deployment = Some(deployment.key());
    Ok(())
}

#[derive(Accounts)]
pub struct CancelImmutableUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = authority,
        constraint = timelock.active_deployment == Some(deployment.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"immutable".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub deployment: Account<'info, Deployment>,
    pub authority: Signer<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn cancel_immutable_upgrade(ctx: Context<CancelImmutableUpgrade>) -> Result<()> {
    let CancelImmutableUpgrade { timelock, .. } = ctx.accounts;
    // Then mark the deployment as inactive
    timelock.active_deployment = None;
    Ok(())
}

#[derive(Accounts)]
pub struct FinalizeImmutableUpgrade<'info> {
    #[account(
        mut,
        close = authority,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = authority,
        constraint = timelock.active_deployment == Some(deployment.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"immutable".as_ref(),
            program.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub deployment: Account<'info, Deployment>,
    /// CHECK:
    pub program: UncheckedAccount<'info>,
    /// CHECK:
    #[account(mut)]
    pub program_data: UncheckedAccount<'info>,
    /// CHECK:
    #[account(mut)]
    pub authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn finalize_immutable_upgrade(ctx: Context<FinalizeImmutableUpgrade>) -> Result<()> {
    let FinalizeImmutableUpgrade {
        timelock,
        deployment,
        program,
        program_data,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    // Verify that the timelock has expired
    let curr_slot = Clock::get()?.slot;
    msg!("Timelock start slot: {}", deployment.slot);
    msg!("Current slot: {}", curr_slot);
    msg!(
        "Slots until expiration: {}",
        timelock
            .timelock_in_slots
            .saturating_sub(curr_slot.saturating_sub(deployment.slot))
    );
    require!(
        curr_slot - deployment.slot >= timelock.timelock_in_slots,
        TimelockError::TimelockNotExpired
    );
    // Upgrade the program
    invoke_signed(
        &bpf_loader_upgradeable::set_upgrade_authority(&program.key(), &timelock.key(), None),
        &[
            program_data.to_account_info(),
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
    timelock.active_deployment = None;
    Ok(())
}
