use dep::std;

// Struct for partial value note witness 
struct PartialValueNoteWitness {
    secret: Field,
    owner: [Field; 2],
    account_required: bool
}

// Struct for partial value note  
struct PartialValueNote {
    secret: Field,
    owner: [Field; 2],
    account_required: bool,
    commitment: Field
}

// Struct for partial claim note witness 
struct PartialClaimNoteWitness {
  deposit_value: u126,
  bridge_call_data_local: Field, // Change to BridgeCallData
  input_nullifier: Field
}

// Struct for partial claim note  
struct PartialClaimNote {
  deposit_value: u126,
  bridge_call_data_local: Field, // Change to BridgeCallData
  partial_value_note_commitment: Field,
  input_nullifier: Field,
  commitment: Field
}

impl PartialValueNote {
    fn new(
        input: PartialValueNoteWitness
    ) -> PartialValueNote {
        let commitment = std::hash::pedersen([
            input.secret, 
            input.owner[0], 
            input.owner[1], 
            input.account_required as Field
        ])[0];
        PartialValueNote {
            secret: input.secret,
            owner: input.owner,
            account_required: input.account_required,
            commitment: commitment
        }
    }
}

impl PartialClaimNote {
    fn new(
        partialValueNote: PartialValueNote,
        input: PartialClaimNoteWitness,
    ) -> PartialClaimNote {
        let commitment = std::hash::pedersen([
            input.deposit_value as Field,
            input.bridge_call_data_local,
            input.input_nullifier, 
            partialValueNote.commitment,
        ])[0];
        PartialClaimNote {
            deposit_value: input.deposit_value,
            bridge_call_data_local: input.bridge_call_data_local,
            partial_value_note_commitment: partialValueNote.commitment,
            input_nullifier: input.input_nullifier,
            commitment: commitment
        }
    }
}