// Claim Circuit Specification: https://docs.aztec.network/spec/claim_circuit
//
// Claim circuit does the following: 
//      -- Spends a user's claim note;
//
//      -- Refers to a particular defi interaction note (which contains uniquely-
//         identifying details of a particular defi interaction);
//
//      -- Outputs up-to two output 'value notes' whose values are proportional 
//         to the amount originally defi-deposited by this user;

use dep::std;
use dep::utils;
use dep::notes;

// Global variable
global DEFI_CLAIM: Field = 1;

fn create_claim_note(claim_note_witness: notes::claim::ClaimNoteWitness) -> notes::claim::ClaimNote {
    let claim_note = notes::claim::ClaimNote::new(claim_note_witness);

    claim_note
}

fn create_defi_interaction_note(defi_note_witness: notes::claim::DeFiNoteWitness) -> notes::claim::DeFiNote {
    let defi_note = notes::claim::DeFiNote::new(defi_note_witness);

    defi_note
}

fn generate_nullifiers(
    claim_note_commitment: Field,
    defi_note_commitment: Field
) -> [Field; 2] {
    let mut nullifiers: [Field; 2] = [0, 0];

    nullifiers[0] = std::hash::pedersen([claim_note_commitment, 9])[0];
    nullifiers[1] = std::hash::pedersen([defi_note_commitment, 9])[0];

    nullifiers
}

fn compute_output_commitments(
    claim_note: notes::claim::ClaimNote,
    output_value_1: Field, 
    output_asset_id_1: Field, 
    output_value_2: Field, 
    output_asset_id_2: Field, 
    nullifiers: [Field; 2]
) -> [Field; 2] {
    let mut output_note_commitments: [Field; 2] = [0, 0];

    output_note_commitments[0] = std::hash::pedersen(
        [
            claim_note.value_note_partial_commitment,
            output_value_1,
            output_asset_id_1,
            nullifiers[0], 
        ]
    )[0];
    
    output_note_commitments[1] = std::hash::pedersen(
        [
            claim_note.value_note_partial_commitment,
            output_value_2,
            output_asset_id_2,
            nullifiers[1], 
        ]
    )[0];

    output_note_commitments
}

fn check_membership_proofs(
    data_root: Field, 
    claim_note_commitment: Field, 
    claim_note_index: Field,
    claim_note_path: [Field; 32],
    defi_note_commitment: Field,
    defi_note_index: Field,
    defi_interaction_note_path: [Field; 32]
) {
    let claim_exists = std::merkle::check_membership(
        data_root,
        claim_note_commitment,
        claim_note_index,
        claim_note_path,
    );
    constrain claim_exists == 1;

    let defi_note_exists = std::merkle::check_membership(
        data_root,
        defi_note_commitment,
        defi_note_index,
        defi_interaction_note_path,
    );
    constrain defi_note_exists == 1;
}


fn main (
    proof_id: pub Field, 
    public_value: pub Field,
    public_owner: pub Field,
    asset_id: pub Field,
    data_root: pub Field,
    fee: pub Field,
    input_asset_id: pub Field,
    defi_deposit_value: pub Field,
    defi_root: pub Field,
    backward_link: pub Field,
    allow_chain: pub Field,
    claim_note_index: Field,
    claim_note_path: [Field; 32],
    claim_note: notes::claim::ClaimNoteWitness,
    defi_note_index: Field,
    defi_interaction_note_path: [Field; 32],
    defi_interaction_note: notes::claim::DeFiNoteWitness,
    output_value_a: Field,
    output_value_b: Field
) -> pub [Field; 15] {
    constrain proof_id == DEFI_CLAIM;

    // Silence unused variables warning
    constrain input_asset_id == 0;
    constrain fee == 0;
    constrain output_value_b == 0;

    // Create claim note
    let claim_note: notes::claim::ClaimNote = create_claim_note(claim_note);

    // Create DeFi interaction note
    let defi_note: notes::claim::DeFiNote = create_defi_interaction_note(defi_interaction_note);

    // Placeholder defi asset id and values
    let mut output_value_1 = claim_note.deposit_value as Field;
    if (defi_note.interaction_result) {
        output_value_1 = output_value_a as Field;
    }
    
    let output_asset_id_1 = 0 as Field;
    let output_value_2 = 0 as Field;
    let output_asset_id_2 = 0 as Field;

    // Check nullifiers are computed correctly
    let nullifiers: [Field; 2] = generate_nullifiers(
        claim_note.commitment,
        defi_note.commitment
    );

    // Compute output commitments 
    let output_commitments = compute_output_commitments(
        claim_note,
        output_value_1,
        output_asset_id_1,
        output_value_2,
        output_asset_id_2,
        nullifiers
    );

    // Check membership proofs of claim and defi note commitments 
    check_membership_proofs(
        data_root, 
        claim_note.commitment, 
        claim_note_index,
        claim_note_path,
        defi_note.commitment,
        defi_note_index,
        defi_interaction_note_path
    );

    // Return public inputs array
    [
        proof_id,
        output_commitments[0],
        output_commitments[1],
        nullifiers[0],
        nullifiers[1],
        public_value,
        public_owner,
        asset_id,
        data_root,
        claim_note.fee,
        claim_note.bridge_call_data,
        defi_deposit_value,
        defi_root,
        backward_link,
        allow_chain
    ]

    // TODO: Add missing range checks and ratio checks!
    // TODO: change number of public outputs to 16
    // TODO: Add bridge call data 
}