// ********************* Value Notes *********************

use dep::std;

// `ValueNoteWitness` struct for value notes
struct ValueNoteWitness {
    value: Field,
    secret: Field,
    owner: [Field; 2],
    asset_id: u32,
    account_required: bool,
    creator_pk: Field,
    input_nullifier: Field,
}

// `ValueNote` struct for value notes
struct ValueNote {
    value: Field,
    secret: Field,
    owner: [Field; 2],
    asset_id: u32,
    account_required: bool,
    creator_pk: Field,
    input_nullifier: Field,
    commitment: Field,
}

impl ValueNote {
    fn new(
        input: ValueNoteWitness
    ) -> ValueNote {
        let commitment = std::hash::pedersen([
            input.secret,
            input.owner[0],
            input.owner[1],
            input.account_required as Field,
            input.creator_pk,
        ])[0];
        ValueNote {
            value: input.value,
            secret: input.secret,
            owner: input.owner,
            asset_id: input.asset_id,
            account_required: input.account_required,
            creator_pk: input.creator_pk,
            input_nullifier: input.input_nullifier,
            commitment: commitment
        }
    }
}