// Account Circuit Specification: https://docs.aztec.network/spec/account_circuit

// Aztec account is composed of (1) the account (public/private key pair) and (2) signers
// (1) is associated with a 'viewing key' to decrypt notes
// (2) is associated with 'spending / signing key' to spend notes

// Unregistered accounts = private key / viewing key (decrypting notes and spending notes )
// Registered accounts =  private key / viewing key (decrypting notes) and seperate registered spending key (spending notes)

use dep::std;
use dep::utils;

fn generate_nullifiers(
    create: u1,
    migrate: u1, 
    alias_hash: Field, 
    new_account_public_key: [Field; 2]
) -> [Field; 2] {
    let mut nullifier_1 = 0;
    let mut nullifier_2 = 0;
    // Account circuit conditionally produces nullifiers
    if (create == 1) | (migrate == 1) {
        nullifier_1 = std::hash::pedersen([alias_hash])[0]; // X EC point in FF
        nullifier_2 = std::hash::pedersen([new_account_public_key[0], new_account_public_key[1]])[0];
    }

    // Return nullifiers
    [nullifier_1, nullifier_2]
}

fn create_account_notes(
    alias_hash : Field, 
    new_account_public_key: [Field; 2], 
    new_signing_public_key_1: [Field; 2], 
    new_signing_public_key_2: [Field; 2]
) -> [Field; 2] {
    // Generate two account note commitments to register two 'spending_public_keys'
    let account_commitment_note_1 = std::hash::pedersen([
        alias_hash,
        new_account_public_key[0],
        new_account_public_key[1],
        new_signing_public_key_1[0],
        new_signing_public_key_1[1]
    ])[0];

    let account_commitment_note_2 = std::hash::pedersen([
        alias_hash,
        new_account_public_key[0],
        new_account_public_key[1],
        new_signing_public_key_2[0],
        new_signing_public_key_2[1]
    ])[0];

    // Return account note commitments 
    [account_commitment_note_1, account_commitment_note_2]
}

fn sign_message(
    create: u1, 
    alias_hash: Field, 
    account_public_key: [Field; 2], 
    new_account_public_key: [Field; 2], 
    new_signing_public_key_1: [Field; 2],
    new_signing_public_key_2: [Field; 2],
    nullifiers: [Field; 2],
    signing_public_key: [Field; 2],
    signature: [u8; 64]
) -> [Field; 2] {
    // Sign with account private key or new spending key
    let mut signer: [Field; 2] = [signing_public_key[0], signing_public_key[1]];
    if create == 1 {
        signer[0] = account_public_key[0];
        signer[1] = account_public_key[1];
    }

    // Constrain that account and signing public keys are not the same
    constrain new_account_public_key != new_signing_public_key_1;
    constrain new_account_public_key != new_signing_public_key_2;

    // Generate signature (account_private_key = first 32-bytes of signature)
    let message = std::hash::pedersen([
        alias_hash, 
        account_public_key[0], 
        new_account_public_key[0],
        new_signing_public_key_1[0],
        new_signing_public_key_2[0],
        nullifiers[0],
        nullifiers[1]
    ])[0];

    // Constrain message output 
    constrain message !=0;

    // Verify schnorr signature
    let message_bytes = utils::field_to_bytes(message);
    let verify_signature = std::schnorr::verify_signature(signer[0], signer[1], signature, message_bytes);

    // Constrain signature verification 
    constrain verify_signature == 1;

    // Return signers
    [signer[0], signer[1]]
}

fn membership_proof(
    tree_root: Field, 
    alias_hash: Field, 
    account_public_key: [Field; 2],
    account_note_index: Field, 
    account_note_path: [Field; 64],
    new_account_public_key: [Field; 2],
    signers: [Field; 2],
    create: u1, 
    migrate: u1,
) {
    let account_note_commitment = std::hash::pedersen([
        alias_hash, 
        account_public_key[0], 
        account_public_key[1], 
        signers[0], signers[1]
    ])[0];
    let member = std::merkle::check_membership(tree_root, account_note_commitment, account_note_index, account_note_path);

    if create == 0 {
        constrain member == 0;
    }
    if migrate == 0 {
        constrain account_public_key == new_account_public_key;
    }
}

fn main (
    tree_root: Field,
    account_public_key: [Field; 2],         // account_private_key * grumpkin.generator
    new_account_public_key: [Field; 2],     // account_private_key * grumpkin.generator
    signing_public_key: [Field; 2],         // signing_private_key (random 256 bits) * grumpkin.generator
    signature: [u8; 64],
    new_signing_public_key_1: [Field; 2],  
    new_signing_public_key_2: [Field; 2],
    alias_hash: Field,
    create: u1,
    migrate: u1,
    account_note_index: Field,              
    account_note_path: [Field; 64],
) -> pub [Field; 16] {
    let proof_id = 0;

    // Constrain modes 
    constrain (create & migrate) == 0;

    // New account registered by generating nullifiers in nullifier tree for 
    // new 'alias_hash' and 'account_public_key'
    let nullifiers: [Field; 2] = generate_nullifiers(
        create, 
        migrate, 
        alias_hash, 
        new_account_public_key
    ); 

    // Create 'account_note' to register 'spending_public_keys' against the account
    // Can register multiple spending keys 
    let account_note: [Field; 2] = create_account_notes(
        alias_hash, 
        account_public_key, 
        new_signing_public_key_1, 
        new_signing_public_key_2
    );

    // Check that a signature over the circuit's inputs has been signed by the 'account_private_key'
    let signers: [Field; 2] = sign_message(
        create, 
        alias_hash, 
        account_public_key, 
        new_account_public_key, 
        new_signing_public_key_1, 
        new_signing_public_key_2, 
        nullifiers, 
        signing_public_key, 
        signature
    );

    // Merkle tree membership of signing account note
    membership_proof(
        tree_root, 
        alias_hash, 
        account_public_key, 
        account_note_index, 
        account_note_path, 
        new_account_public_key, 
        signers, 
        create, 
        migrate
    );

    // Public values set to 0
    let public_value = 0;
    let public_owner = 0;
    let asset_id = 0;
    let tx_fee = 0;
    let tx_fee_asset_id = 0;
    let bridge_call_data = 0;
    let defi_deposit_value = 0;
    let defi_root = 0;
    let backward_link = 0;
    let allow_chain = 0;

    // Public outputs
    [
        proof_id,
        account_note[0],
        account_note[1],
        nullifiers[0],
        nullifiers[1],
        public_value,
        public_owner,
        asset_id,
        tree_root,
        tx_fee,
        tx_fee_asset_id,
        bridge_call_data,
        defi_deposit_value,
        defi_root,
        backward_link,
        allow_chain
    ]
}
