// Account Circuit Specification: https://docs.aztec.network/spec/account_circuit
//
//      There are two types of Aztec accounts --> Registered and Unregistered:
//          1. Registered accounts are associated with (1) public/private key-pair and (2) signers, where
//              (1) represents a 'private or viewing key' to decrypt value notes 
//              (2) represents a 'spending / signing key' to spend notes and sign transactions
//
//          2. Unregistered accounts are only associated with (1) public/private key-pair, where
//          the private key acts like both the 'viewing key' and 'spending key' for the account.
//
//      `Account Abstraction` takes advantage of the functional seperation of viewing and spending keys,
//      allowing a registered account to have an arbitrary number of spending keys. This allows an account 
//      to spend notes on multiple devices without sharing keys.

use dep::std;
use dep::utils;
use dep::notes;

// Register new account by generating nullifiers (stored in nullifier tree) for 
// new 'alias_hash' and 'account_public_key'
fn generate_nullifiers(
    create: u1,
    migrate: u1, 
    alias_hash: Field, 
    account_public_key: [Field; 2]
) -> [Field; 2] {
    let mut nullifier_1 = 0;
    let mut nullifier_2 = 0;
    // Account circuit conditionally produces nullifiers
    if (create == 1) {
        nullifier_1 = std::hash::pedersen([alias_hash])[0];
    }
    if ((create == 1) | (migrate == 1)) {
        nullifier_2 = std::hash::pedersen([account_public_key[0], account_public_key[1]])[0];
    }

    [nullifier_1, nullifier_2]
}

// Create account notes to register 'spending_public_keys' against the account
fn create_account_notes(
    note_1: notes::account::Witness,
    note_2: notes::account::Witness
) -> [Field; 2] {
    // Construct account notes and commitments from witness to associate 'spending_public_keys' with account
    let account_note_1 = notes::account::Account::new(note_1);
    let account_note_2 = notes::account::Account::new(note_2);

    [account_note_1.commitment, account_note_2.commitment]
}

// Check that a signature over the circuit's inputs has been signed by the 'account_private_key'
fn sign_message(
    create: u1, 
    migrate: u1, 
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

    // Constrain modes 
    constrain (create & migrate) == 0;

    // Constrain that account and signing public keys are not the same
    constrain new_account_public_key != new_signing_public_key_1;
    constrain new_account_public_key != new_signing_public_key_2;

    if (migrate == 0) { 
       constrain account_public_key == new_account_public_key;
    }

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
    constrain message == 1;

    // Verify schnorr signature
    let message_bytes = utils::field_to_bytes(message);
    let verify_signature = std::schnorr::verify_signature(signer[0], signer[1], signature, message_bytes);

    // Constrain signature verification 
    constrain verify_signature == 1;

    // Return signers
    [signer[0], signer[1]]
}

// Merkle tree membership to check whether signing account notes exist if create !=0
fn membership_proof(
    tree_root: Field, 
    alias_hash: Field, 
    account_note_index: Field, 
    account_note_path: [Field; 64],
    new_account_public_key: [Field; 2],
    signers: [Field; 2],
    create: u1 
) {
    let account_note_commitment = std::hash::pedersen([
        alias_hash, 
        new_account_public_key[0], 
        new_account_public_key[1], 
        signers[0], signers[1]
    ])[0];
    
    let member = std::merkle::check_membership(tree_root, account_note_commitment, account_note_index, account_note_path);

    if create == 0 {
        constrain member == 0;
    }
}

fn main (
    // Private inputs
    tree_root: Field,
    account_public_key: [Field; 2],         // account_private_key * grumpkin.generator
    new_account_public_key: [Field; 2],     // account_private_key * grumpkin.generator
    signing_public_key: [Field; 2],         // signing_private_key (random 256 bits) * grumpkin.generator
    signature: [u8; 64],                    // signature using account_private_key
    new_signing_public_key_1: [Field; 2],   // public key associated with signing key
    new_signing_public_key_2: [Field; 2],   // public key associated with signing key
    alias_hash: Field,                      // 224-bit field element
    create: u1,                             // `create` mode
    migrate: u1,                            // `migrate` mode
    account_note_index: Field,              // index of account note in commitment tree        
    account_note_path: [Field; 64],         // path of account note in commitment tree
    note_1: notes::account::Witness,        // witness for note 1
    note_2: notes::account::Witness,        // witness for note 2
) -> pub [Field; 16] {
    let nullifiers: [Field; 2] = generate_nullifiers(
        create, 
        migrate, 
        alias_hash, 
        account_public_key,
    ); 

    let account_note_commitments: [Field; 2] = create_account_notes(
        note_1, 
        note_2
    );

    let signers: [Field; 2] = sign_message(
        create, 
        migrate,
        alias_hash, 
        account_public_key, 
        new_account_public_key, 
        new_signing_public_key_1, 
        new_signing_public_key_2, 
        nullifiers, 
        signing_public_key, 
        signature
    );

    membership_proof(
        tree_root, 
        alias_hash, 
        account_note_index, 
        account_note_path, 
        new_account_public_key, 
        signers, 
        create
    );
    
    let proof_id = 0;
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

    // @dev Rollup circuit enforces that inner circuits must have the same number of public inputs.
    // Return public inputs
    [
        proof_id,
        account_note_commitments[0],
        account_note_commitments[1],
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