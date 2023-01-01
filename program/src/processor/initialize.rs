use anchor_lang::prelude::*;
use anchor_lang::solana_program::{bpf_loader_upgradeable, program::invoke};

use crate::{
    BpfLoaderUpgradeable, TimelockAuthority, MAX_TIMELOCK_DURATION, MIN_TIMELOCK_DURATION,
};

#[derive(Accounts)]
pub struct InitializeTimelock<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [
            b"timelock-authority".as_ref(),
            program.key().as_ref(),
        ],
        bump,
        space = 8 + 32 + 8 + 32 + 33
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    /// CHECK:
    pub program: UncheckedAccount<'info>,
    #[account(mut)]
    /// CHECK:
    pub program_data: UncheckedAccount<'info>,
    pub program_authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
    pub bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,
}

pub fn initialize_and_assign_timelock_authority(
    ctx: Context<InitializeTimelock>,
    timelock_in_slots: u64, // WARNING, you will NOT be able to change this after initialization
) -> Result<()> {
    let InitializeTimelock {
        timelock,
        program,
        program_data,
        program_authority,
        bpf_loader_upgradeable_program,
        ..
    } = ctx.accounts;
    let timelock_duration = timelock_in_slots
        .min(MAX_TIMELOCK_DURATION)
        .max(MIN_TIMELOCK_DURATION);
    msg!("Timelock duration: {} slots", timelock_duration);
    **timelock = TimelockAuthority {
        authority: program_authority.key(),
        timelock_in_slots: timelock_duration,
        program_id: program.key(),
        active_deployment: None,
    };
    // Downstream CPI performs the validation
    invoke(
        &bpf_loader_upgradeable::set_upgrade_authority(
            &program.key(),
            &program_authority.key(),
            Some(&timelock.key()),
        ),
        &[
            program_data.to_account_info(),
            program_authority.to_account_info(),
            timelock.to_account_info(),
            bpf_loader_upgradeable_program.to_account_info(),
        ],
    )?;
    Ok(())
}
