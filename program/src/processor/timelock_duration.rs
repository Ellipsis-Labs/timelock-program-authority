use anchor_lang::prelude::*;
use crate::{ModifyDurationUpgrade, TimelockAuthority, TimelockError, MAX_TIMELOCK_DURATION, MIN_TIMELOCK_DURATION};

#[derive(Accounts)]
pub struct InitializeModifyTimelockDuration<'info> {
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
            b"modify-timelock".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        space = 8 + 8 + 32 + 8 
    )]
    pub modify_duration_upgrade: Account<'info, ModifyDurationUpgrade>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_modify_timelock_duration_upgrade(ctx: Context<InitializeModifyTimelockDuration>, new_timelock_duration_in_slots: u64) -> Result<()> {
    let InitializeModifyTimelockDuration {
        timelock,
        modify_duration_upgrade,
        payer,
        ..
    } = ctx.accounts;
    let clock = Clock::get()?;
    // Create an immutable upgrade and start the countdown
    **modify_duration_upgrade = ModifyDurationUpgrade {
        initialization_slot: clock.slot,
        payer: payer.key(),
        new_timelock_duration_in_slots: new_timelock_duration_in_slots.min(MAX_TIMELOCK_DURATION).max(MIN_TIMELOCK_DURATION),
    };
    // Then update the timelock authority to reflect the upgrade in progress
    timelock.active_upgrade = Some(modify_duration_upgrade.key());
    Ok(())
}

#[derive(Accounts)]
pub struct CancelModifyTimelockDuration<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        has_one = authority,
        constraint = timelock.active_upgrade == Some(modify_duration_upgrade.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"modify-timelock".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub modify_duration_upgrade: Account<'info, ModifyDurationUpgrade>,
    pub authority: Signer<'info>,
    /// CHECK:
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}

pub fn cancel_modify_timelock_duration_upgrade(ctx: Context<CancelModifyTimelockDuration>) -> Result<()> {
    let CancelModifyTimelockDuration { timelock, .. } = ctx.accounts;
    // Mark the upgrade as inactive
    timelock.active_upgrade = None;
    Ok(())
}

#[derive(Accounts)]
pub struct FinalizeModifyTimelockDuration<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        constraint = timelock.active_upgrade == Some(modify_duration_upgrade.key()),
    )]
    pub timelock: Account<'info, TimelockAuthority>,
    #[account(
        mut,
        close = payer,
        seeds = [
            b"modify-timelock".as_ref(),
            timelock.key().as_ref(),
        ],
        bump,
        has_one = payer,
    )]
    pub modify_duration_upgrade: Account<'info, ModifyDurationUpgrade>,
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}

pub fn finalize_modify_timelock_duration_upgrade(ctx: Context<FinalizeModifyTimelockDuration>) -> Result<()> {
    let FinalizeModifyTimelockDuration {
        timelock,
        modify_duration_upgrade,
        ..
    } = ctx.accounts;
    // Verify that the timelock has expired
    let curr_slot = Clock::get()?.slot;
    msg!(
        "Timelock start slot: {}",
        modify_duration_upgrade.initialization_slot
    );
    msg!("Current slot: {}", curr_slot);
    msg!(
        "Slots until expiration: {}",
        timelock
            .timelock_duration_in_slots
            .saturating_sub(curr_slot.saturating_sub(modify_duration_upgrade.initialization_slot))
    );
    require!(
        curr_slot - modify_duration_upgrade.initialization_slot >= timelock.timelock_duration_in_slots,
        TimelockError::TimelockNotExpired
    );
    // Upgrade the timelock 
    timelock.timelock_duration_in_slots = modify_duration_upgrade.new_timelock_duration_in_slots;
    // Then mark the deployment as inactive
    timelock.active_upgrade = None;
    Ok(())
}

