use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum SolayerInstruction {
    /// Accounts expected:
    ///
    SigVerify {
        pubkey: Pubkey,
        signature: Vec<u8>,
        message: Vec<u8>,
        ed25519_program_id: Pubkey,
    },
}
