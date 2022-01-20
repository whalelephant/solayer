use thiserror::Error;

use solana_program::program_error::ProgramError;

#[derive(Error, Debug, Copy, Clone)]
pub enum SolayerError {
    /// Invalid instruction
    #[error("Invalid Instruction")]
    InvalidInstruction,
    #[error("NoRentExempt")]
    NotRentExempt,
}

impl From<SolayerError> for ProgramError {
    fn from(e: SolayerError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
