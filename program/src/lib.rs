pub mod error;
pub mod processor;
pub mod state;

use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;
pub use error::*;
pub use processor::*;
pub use state::*;

declare_id!("timeC3R5LwchSqLTgHdLnFedunV4X8zed65sVZtGxhP");

pub const MIN_TIMELOCK_DURATION: u64 = 1440; // ~1 hour at 2.5 slots per second
pub const MAX_TIMELOCK_DURATION: u64 = 483840; // ~2 weeks at 2.5 slots per second

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
        &crate::id(),
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
        &crate::id(),
    )
    .0
}

pub fn get_immutable_deployment_address(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"immutable".as_ref(), program_id.as_ref()], &crate::id()).0
}

#[program]
pub mod timelock_program_authority {

    use super::*;
    pub fn initialize_and_assign_timelock_authority(
        ctx: Context<InitializeTimelock>,
        timelock_in_slots: u64, // WARNING, you will NOT be able to change this after initialization
    ) -> Result<()> {
        initialize::initialize_and_assign_timelock_authority(ctx, timelock_in_slots)
    }

    pub fn initialize_program_upgrade(ctx: Context<InitializeProgramUpgrade>) -> Result<()> {
        program_upgrade::initialize_program_upgrade(ctx)
    }

    pub fn cancel_program_upgrade(ctx: Context<CancelProgramUpgrade>) -> Result<()> {
        program_upgrade::cancel_program_upgrade(ctx)
    }

    pub fn finalize_program_upgrade(ctx: Context<FinalizeProgramUpgrade>) -> Result<()> {
        program_upgrade::finalize_program_upgrade(ctx)
    }

    pub fn initialize_immutable_upgrade(ctx: Context<InitializeImmutableUpgrade>) -> Result<()> {
        immutable_upgrade::initialize_immutable_upgrade(ctx)
    }

    pub fn cancel_immutable_upgrade(ctx: Context<CancelImmutableUpgrade>) -> Result<()> {
        immutable_upgrade::cancel_immutable_upgrade(ctx)
    }

    pub fn finalize_immutable_upgrade(ctx: Context<FinalizeImmutableUpgrade>) -> Result<()> {
        immutable_upgrade::finalize_immutable_upgrade(ctx)
    }
}
