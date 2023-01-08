// Join-Split Circuit Specification: https://docs.aztec.network/spec/join_split_circuit
//
//  'Join-Split' circuit allows notes to be spent. The circuit takes in two input notes, 
//  and two new output notes, and updates the Note Tree and Nullifier Tree accordingly.

use dep::std;
use dep::utils;
use dep::notes;

// Global network constants
global NUM_ASSETS_BIT_LENGTH: Field = 2;
global NUM_ASSETS: Field = 1;
global DATA_TREE_DEPTH: Field = 32;
global NULL_TREE_DEPTH: Field = 256;
global ROOT_TREE_DEPTH: Field = 28;
global MAX_TXS_BIT_LENGTH: Field = 10;
global NOTE_VALUE_BIT_LENGTH: Field = 252;
global TX_FEE_BIT_LENGTH: Field = 244; 
global ALIAS_HASH_BIT_LENGTH = 224; 

// DeFi global variables 
global DEPOSIT: Field = 1;
global WITHDRAW: Field = 1;
global SEND: Field = 1;
global DEFI_DEPOSIT: Field = 1;

fn derive_public_key(account_private_key: Field) -> [Field; 2] {
    constrain account_private_key != 0;
    let account_public_key = std::scalar_mul::fixed_base(account_private_key);

    account_public_key
}

fn derive_signer_pk(
    account_public_key: [Field; 2],
    signing_pk: [Field; 2],
    account_required: bool
) -> [Field; 2] {
    let mut signer_pk: [Field; 2] = account_public_key;
    if account_required {
        signer_pk = signing_pk; 
    }

    signer_pk
}

fn create_account_notes(account_note_witness: notes::account::AccountWitness) -> notes::account::Account {
    let account_note = notes::account::Account::new(account_note_witness);
    
    account_note
}

fn create_value_notes(
    input_note_1: notes::value::ValueNoteWitness,
    input_note_2: notes::value::ValueNoteWitness,
    output_note_1: notes::value::ValueNoteWitness,
    output_note_2: notes::value::ValueNoteWitness,
) -> [notes::value::ValueNote; 4] {
    let input_value_note_1 = notes::value::ValueNote::new(input_note_1);
    let input_value_note_2 = notes::value::ValueNote::new(input_note_2);
    let output_value_note_1 = notes::value::ValueNote::new(output_note_1);
    let output_value_note_2 = notes::value::ValueNote::new(output_note_2);

    constrain (input_value_note_1.commitment != input_value_note_2.commitment);

    [input_value_note_1, input_value_note_2, output_value_note_1, output_value_note_2]
}
    
fn membership_proof_account_notes(
    tree_root: Field, 
    account_note_index: Field, 
    account_note_path: [Field; 32],
    account_note: notes::account::Account
) {
    let signing_key_member = std::merkle::check_membership(
        tree_root, 
        account_note.commitment, 
        account_note_index, 
        account_note_path
    );
    
    constrain signing_key_member != 0;
}

fn membership_proof_value_notes(
    tree_root: Field,
    input_note_1_index: Field,
    input_note_2_index: Field,
    input_note_1_path: [Field; 32],
    input_note_2_path: [Field; 32],
    value_notes: [notes::value::ValueNote; 4], 
) {
    let signing_key_member_input_1 = std::merkle::check_membership(
        tree_root, 
        value_notes[0].commitment, 
        input_note_1_index, 
        input_note_1_path
    );
    let signing_key_member_input_2 = std::merkle::check_membership(
        tree_root, 
        value_notes[1].commitment, 
        input_note_2_index, 
        input_note_2_path
    );

    constrain signing_key_member_input_1 != 0;
    constrain signing_key_member_input_2 != 0;
}

fn generate_nullifiers(
    account_private_key: Field,
    value_notes: [notes::value::ValueNote; 4]
) -> [Field; 2] {
    let mut nullifiers: [Field; 2] = [0, 0];
    let hashed_private_key = std::scalar_mul::fixed_base(account_private_key);

    nullifiers[0] = std::hash::pedersen(
        [
            value_notes[0].commitment, hashed_private_key[0], hashed_private_key[1]
        ]
    )[0];
    nullifiers[1] = std::hash::pedersen(
        [
            value_notes[1].commitment, hashed_private_key[0], hashed_private_key[1]
        ]
    )[0];

    // nullifier constrains 
    constrain value_notes[2].input_nullifier == nullifiers[0];
    constrain value_notes[3].input_nullifier == nullifiers[1];

    nullifiers
}

fn verify_signature(
    public_value: Field,
    public_owner: Field,
    output_note_commitment_1: Field,
    output_note_commitment_2: Field,
    signers: [Field; 2],
    signature: [u8; 64],
    nullifiers: [Field; 2],
    backward_link: Field,
    allow_chain: Field
) {
    let message = std::hash::pedersen(
        [
            public_value,
            public_owner, 
            output_note_commitment_1, 
            output_note_commitment_2, 
            nullifiers[0], 
            nullifiers[1],
            backward_link,
            allow_chain
        ]
    )[0];

    let message_bytes = utils::field_to_bytes(message);
    
    let sig_res = std::schnorr::verify_signature(
       signers[0],  
       signers[1], 
       signature, 
       message_bytes
    );

    constrain sig_res == 1;
}

fn create_partial_value_note(partial_value_note_witness: notes::claim::PartialValueNoteWitness) -> notes::claim::PartialValueNote {
    let partial_value_note = notes::claim::PartialValueNote::new(partial_value_note_witness);

    partial_value_note
}

fn create_partial_claim_note(
    partial_value_note: notes::claim::PartialValueNote,
    partial_claim_note_witness: notes::claim::PartialClaimNoteWitness
) -> notes::claim::PartialClaimNote {
    let partial_claim_note = notes::claim::PartialClaimNote::new(
        partial_value_note,
        partial_claim_note_witness
    );
    
    partial_claim_note
}

fn main (
    asset_id: Field, 
    num_input_notes: Field,
    input_note_1_index: Field,
    input_note_2_index: Field, 
    input_note_1_path: [Field; 32],
    input_note_2_path: [Field; 32],
    input_note_1: notes::value::ValueNoteWitness,
    input_note_2: notes::value::ValueNoteWitness,
    output_note_1: notes::value::ValueNoteWitness,
    output_note_2: notes::value::ValueNoteWitness,
    account_note_witness: notes::account::AccountWitness,
    partial_value_note_data: notes::claim::PartialValueNoteWitness,
    partial_claim_note_data: notes::claim::PartialClaimNoteWitness,
    account_private_key: Field,
    alias_hash: Field,
    account_required: bool, 
    account_note_index: Field,
    account_note_path: [Field; 32],
    signing_pk: [Field; 2],
    signature: [u8; 64],
    proof_id: pub Field,
    output_note_commitment_1: pub Field,
    output_note_commitment_2: pub Field,
    public_value: pub Field,
    public_owner: pub Field,
    old_data_tree_root: pub u32,
    tx_fee: pub u32,
    tx_fee_asset_id: pub u32,
    bridge_call_data: pub Field,
    defi_deposit_value: pub Field,
    defi_root: pub Field,
    backward_link: pub Field, 
    allow_chain: pub Field,
    tree_root: pub Field
) -> pub [Field; 16] {
    // Silence unused variables warning
    constrain allow_chain == 0;
    constrain backward_link == 0;
    constrain defi_deposit_value == 0;
    constrain bridge_call_data == 0;
    constrain tx_fee_asset_id == 0;
    constrain defi_root == 0;
    constrain old_data_tree_root == 0;

    // Range checks w/ explicit type casting
    constrain input_note_1_index as u64 < ((2 << DATA_TREE_DEPTH) as u64 );
    constrain input_note_2_index as u64 < ((2 << DATA_TREE_DEPTH) as u64);
    constrain input_note_1.value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);
    constrain input_note_2.value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);
    constrain output_note_1.value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);
    constrain output_note_2.value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);    
    constrain asset_id as u64< ((2 << NUM_ASSETS_BIT_LENGTH) as u64);
    constrain public_value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);
    constrain tx_fee as u64< ((2 << TX_FEE_BIT_LENGTH) as u64);
    constrain account_note_index as u64 < ((2 << DATA_TREE_DEPTH) as u64);
    constrain alias_hash as u64 < ((2 << ALIAS_HASH_BIT_LENGTH) as u64);
    constrain account_required as u64 < 2;
    constrain num_input_notes == 2;
    constrain partial_claim_note_data.deposit_value as u64 < ((2 << NOTE_VALUE_BIT_LENGTH) as u64);

    // Constrain notes above max output notes do not carry value
    if (num_input_notes < 2) { 
        constrain input_note_2.value == 0;
    }
    if (num_input_notes < 1) {
        constrain input_note_1.value == 0;
    }

    // Public value initialisations
    let mut public_asset_id = 0;
    let mut public_input = 0;
    let mut public_output = 0;

    // DeFi transaction type initialisations
    let is_deposit = proof_id == DEPOSIT;
    let is_withdraw = proof_id == WITHDRAW;
    let is_send = proof_id == SEND;
    let is_defi_deposit = proof_id == DEFI_DEPOSIT;
    let is_public_tx = is_deposit | is_withdraw;

    if is_public_tx {
        public_asset_id = asset_id; 
    }
    if is_deposit {
        public_input = public_value; 
    }
    if is_withdraw {
        public_output = public_value; 
    } 

    constrain is_deposit | is_withdraw | is_send | is_defi_deposit;

    // Asset Type Checks
    constrain input_note_1.asset_id == input_note_2.asset_id;
    constrain output_note_1.asset_id == input_note_2.asset_id as u32;
    constrain output_note_2.asset_id == output_note_1.asset_id as u32;
    constrain public_asset_id as u32 == input_note_1.asset_id as u32;
    constrain public_input != 0;

    // Conservation of notes: Notes In == Notes Out
    let total_in_value = public_input + input_note_1.value + input_note_2.value;
    let total_out_value = public_output + output_note_1.value + output_note_2.value;
    constrain total_in_value == total_out_value;

    // Transaction fee
    let tx_fee = total_in_value - total_out_value; // (no underflow allowed)

    // Data validity checks
    constrain (num_input_notes == 0 | 1 | 2);
    constrain (is_deposit | is_send | is_withdraw | is_defi_deposit);

    if num_input_notes == 0 {
        constrain is_deposit;
    }

    if (is_public_tx) {
        constrain (public_value > 0);
        constrain (public_owner > 0);
    } else {
        constrain (public_value == 0);
        constrain (public_owner == 0);
    }

    // Create account notes from witness
    let account_note: notes::account::Account = create_account_notes(
        account_note_witness
    );

    // Create value notes from witness
    let value_notes: [notes::value::ValueNote; 4] = create_value_notes(
        input_note_1, 
        input_note_2,
        output_note_1,
        output_note_2
    );

    // Derive public key from private key
    let account_public_key: [Field; 2] = derive_public_key(account_private_key);
    
    // public key constraints
    constrain (account_public_key == input_note_1.owner);
    constrain (account_public_key == input_note_2.owner);
    constrain (account_required == input_note_1.account_required);
    constrain (account_required == input_note_2.account_required);

    if (output_note_1.creator_pk == 0) {
        constrain (account_public_key[0] == output_note_1.creator_pk);
    }
    if (output_note_2.creator_pk == 0) {
        constrain (account_public_key[0] == output_note_2.creator_pk);
    }

    // Check chained transaction inputs are valid:
    let backward_link_in_use = backward_link != 0;
    let note1_propagated = backward_link == value_notes[0].commitment;
    let note2_propagated = backward_link == value_notes[1].commitment;
    if backward_link_in_use {
        constrain (note1_propagated | note2_propagated);
    }
    if is_defi_deposit {
        constrain allow_chain != 1;
    }
    if allow_chain == 1 {
        constrain output_note_1.owner == input_note_1.owner;
    }
    if allow_chain == 2 {
        constrain output_note_2.owner == input_note_1.owner;
    }

    // Constrain unused public inputs to zero
    constrain defi_root == 0;

    // Derive signer key
    let signer_pk: [Field; 2] = derive_signer_pk(
        account_public_key,
        signing_pk, 
        account_required
    );
   
    // Verify account ownership with membership proof
    membership_proof_account_notes(
        tree_root, 
        account_note_index, 
        account_note_path, 
        account_note
    );

    // Verify value notes with membership proof
    membership_proof_value_notes(
        tree_root, 
        input_note_1_index,
        input_note_2_index, 
        input_note_1_path,
        input_note_2_path,
        value_notes
    );

    // Check nullifiers are computed correctly
    let nullifiers: [Field; 2] = generate_nullifiers(
        account_private_key,
        value_notes
    );

    // Verify signature
    verify_signature(
        public_value,
        public_owner, 
        output_note_commitment_1,
        output_note_commitment_2,
        signer_pk, 
        signature, 
        nullifiers,
        backward_link,
        allow_chain
    );

    // DeFi deposit 
    let mut output_note_1_commitment = value_notes[0].commitment; 
    let mut input_note_2_value = value_notes[1].value;
    let mut output_note_1_value = output_note_1.value;
    let mut defi_deposit_value = 0;

    if is_defi_deposit {
        // Create partial value note
        let partial_value_note: notes::claim::PartialValueNote = create_partial_value_note(partial_value_note_data);

        // Create partial claim note
        let partial_claim_note: notes::claim::PartialClaimNote = create_partial_claim_note(
            partial_value_note,
            partial_claim_note_data
        );

        // DeFi transaction constraints
        output_note_1_commitment = partial_claim_note.commitment;
        defi_deposit_value = partial_claim_note.deposit_value;

        constrain (defi_deposit_value > 0);

        let one_input_note = num_input_notes >= 1;
        let two_input_notes = num_input_notes == 2;
        constrain one_input_note | two_input_notes;

        let input_note_1_in_use = one_input_note | two_input_notes;
        let input_note_2_in_use = two_input_notes;

        constrain input_note_1_in_use == true;

        if (input_note_2_in_use & (input_note_1.asset_id != input_note_2.asset_id)) {
            constrain (defi_deposit_value as Field == input_note_2.value);
            input_note_2_value = 0; 
        }

        output_note_1_value = 0; 
    }

    // Return public inputs array
    [
        proof_id,
        value_notes[2].commitment,
        value_notes[3].commitment,
        nullifiers[0],
        nullifiers[1],
        public_value,
        public_owner,
        public_asset_id,
        old_data_tree_root as Field,
        tx_fee,
        asset_id,
        bridge_call_data,
        defi_deposit_value as Field,
        defi_root,
        backward_link,
        allow_chain
    ]
}