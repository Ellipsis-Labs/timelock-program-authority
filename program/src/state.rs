use anchor_lang::prelude::*;

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
