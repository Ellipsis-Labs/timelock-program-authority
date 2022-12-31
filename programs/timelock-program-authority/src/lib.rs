use anchor_lang::{
    prelude::*,
    solana_program::{bpf_loader_upgradeable, program::invoke},
};

const MIN_TIMELOCK_DURATION: u64 = 1440; // ~1 hour at 2.5 slots per second
const MAX_TIMELOCK_DURATION: u64 = 483840; // ~2 weeks at 2.5 slots per second

#[derive(Clone)]
pub struct BpfLoaderUpgradeable;

impl anchor_lang::Id for BpfLoaderUpgradeable {
    fn id() -> Pubkey {
        bpf_loader_upgradeable::id()
    }
}

pub fn get_timelock_address(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[b"timelock-authority".as_ref(), program_id.as_ref()],
        &id(),
    )
    .0
}

pub fn get_deployment_address(program_id: &Pubkey, buffer: &Pubkey, payer: &Pubkey) -> Pubkey {
    let timelock = get_timelock_address(program_id);
    Pubkey::find_program_address(
        &[
            b"timelock-deployment".as_ref(),
            timelock.as_ref(),
            payer.as_ref(),
            buffer.as_ref(),
        ],
        &id(),
    )
    .0
}

pub fn get_immutable_deployment_address(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"immutable".as_ref(), program_id.as_ref()], &id()).0
}

declare_id!("timeC3R5LwchSqLTgHdLnFedunV4X8zed65sVZtGxhP");

#[program]
pub mod timelock_program_authority {

    use anchor_lang::solana_program::program::invoke_signed;

    use super::*;
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
            slot: clock.slot,
            payer: payer.key(),
            buffer: buffer.key(),
        };
        // Then update the timelock authority to reflect the upgrade in progress
        timelock.active_deployment = Some(deployment.key());
        Ok(())
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
        timelock.active_deployment = None;
        Ok(())
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
        timelock.active_deployment = None;
        Ok(())
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

    pub fn cancel_immutable_upgrade(ctx: Context<CancelImmutableUpgrade>) -> Result<()> {
        let CancelImmutableUpgrade { timelock, .. } = ctx.accounts;
        // Then mark the deployment as inactive
        timelock.active_deployment = None;
        Ok(())
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
}

#[account]
pub struct TimelockAuthority {
    pub authority: Pubkey,
    pub timelock_in_slots: u64,
    pub program_id: Pubkey,
    pub active_deployment: Option<Pubkey>,
}

#[account]
pub struct Deployment {
    pub slot: u64,
    pub payer: Pubkey,
    pub buffer: Pubkey,
}

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
        constraint = timelock.active_deployment == None,
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
        constraint = timelock.active_deployment == Some(deployment.key()),
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

#[derive(Accounts)]
pub struct FinalizeProgramUpgrade<'info> {
    #[account(
        mut,
        seeds = [
            b"timelock-authority".as_ref(),
            timelock.program_id.as_ref(),
        ],
        bump,
        constraint = timelock.active_deployment == Some(deployment.key()),
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

#[error_code]
pub enum TimelockError {
    #[msg("Program is not executable")]
    ProgramNotExecutable,
    #[msg("Incorrect program data owner")]
    ProgramDataOwnerIncorrect,
    #[msg("Incorrect program data address")]
    ProgramDataAddressIncorrect,
    #[msg("Invalid program data account data")]
    InvalidProgramDataAccountData,
    #[msg("Incorrect program upgrade authority")]
    ProgramUpgradeAuthorityIncorrect,
    #[msg("Program upgrade authority not set")]
    ProgramUpgradeAuthorityNotSet,
    #[msg("Timelock not expired")]
    TimelockNotExpired,
}
