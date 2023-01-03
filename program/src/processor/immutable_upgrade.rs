use anchor_lang::prelude::*;
use anchor_lang::solana_program::{bpf_loader_upgradeable, program::invoke_signed};

use crate::{BpfLoaderUpgradeable, ImmutableUpgrade, TimelockAuthority, TimelockError};

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
        constraint = timelock.active_upgrade == None,
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        init,
        payer = payer,
        seeds = [
            b"immutable".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        space = 8 + 8 + 32
    )]
    pub immutable_upgrade: Account<'info, ImmutableUpgrade>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_immutable_upgrade(ctx: Context<InitializeImmutableUpgrade>) -> Result<()> {
    let InitializeImmutableUpgrade {
        timelock,
        immutable_upgrade,
        payer,
        ..
    } = ctx.accounts;
    let clock = Clock::get()?;
    // Create an immutable upgrade and start the countdown
    **immutable_upgrade = ImmutableUpgrade {
        initialization_slot: clock.slot,
        payer: payer.key(),
    };
    // Then update the timelock authority to reflect the upgrade in progress
    timelock.active_upgrade = Some(immutable_upgrade.key());
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
        constraint = timelock.active_upgrade == Some(immutable_upgrade.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"immutable".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub immutable_upgrade: Account<'info, ImmutableUpgrade>,
    pub authority: Signer<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn cancel_immutable_upgrade(ctx: Context<CancelImmutableUpgrade>) -> Result<()> {
    let CancelImmutableUpgrade { timelock, .. } = ctx.accounts;
    // Then mark the deployment as inactive
    timelock.active_upgrade = None;
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
        constraint = timelock.active_upgrade == Some(immutable_upgrade.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"immutable".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub immutable_upgrade: Account<'info, ImmutableUpgrade>,
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
        immutable_upgrade,
        program,
        program_data,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    // Verify that the timelock has expired
    let curr_slot = Clock::get()?.slot;
    msg!(
        "Timelock start slot: {}",
        immutable_upgrade.initialization_slot
    );
    msg!("Current slot: {}", curr_slot);
    msg!(
        "Slots until expiration: {}",
        timelock
            .timelock_duration_in_slots
            .saturating_sub(curr_slot.saturating_sub(immutable_upgrade.initialization_slot))
    );
    require!(
        curr_slot - immutable_upgrade.initialization_slot >= timelock.timelock_duration_in_slots,
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
    timelock.active_upgrade = None;
    Ok(())
}
