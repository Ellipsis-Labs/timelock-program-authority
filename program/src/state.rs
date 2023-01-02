use anchor_lang::prelude::*;

#[account]
pub struct TimelockAuthority {
    pub authority: Pubkey,
    pub timelock_duration_in_slots: u64,
    pub program_id: Pubkey,
    pub active_upgrade: Option<Pubkey>,
}

/// This struct is used to represent a pending program upgrade.
#[account]
pub struct Deployment {
    pub initialization_slot: u64,
    pub payer: Pubkey,
    pub buffer: Pubkey,
}

/// This struct is used to represent a pending request to make the program immutable.
#[account]
pub struct ImmutableUpgrade {
    pub initialization_slot: u64,
    pub payer: Pubkey,
}

/// This struct is used to represent a pending request to change the timelock duration.
#[account]
pub struct ModifyDurationUpgrade {
    pub initialization_slot: u64,
    pub payer: Pubkey,
    pub new_timelock_duration_in_slots: u64,
}
