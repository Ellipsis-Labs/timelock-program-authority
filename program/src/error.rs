use anchor_lang::prelude::*;

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
