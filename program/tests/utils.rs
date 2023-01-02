use std::{fs::File, io::Read};

use solana_sdk::signature::Keypair;

pub fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::from_bytes(&keypair.to_bytes()).unwrap()
}

pub fn read_elf(program_location: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(program_location)
        .map_err(|err| format!("Unable to open program file {}: {}", program_location, err))?;
    let mut program_data = Vec::new();
    file.read_to_end(&mut program_data)
        .map_err(|err| format!("Unable to open program file {}: {}", program_location, err))?;
    // Skip verification of the program for testing
    Ok(program_data)
}
