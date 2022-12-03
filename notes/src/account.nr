use dep::std;

// Account struct for account notes
struct Note {
    alias_hash: Field, 
    account_public_key: [Field; 2], 
    signing_public_key: [Field; 2],
    commitment: Field,
}

impl Note {
    fn new(
        input: Witness
    ) -> Note {
        let commitment = std::hash::pedersen([
            input.alias_hash, 
            input.account_public_key[0], 
            input.account_public_key[1], 
            input.signing_public_key[0], 
            input.signing_public_key[1]
        ])[0];
        Note {
            alias_hash: input.alias_hash,
            account_public_key: input.account_public_key,
            signing_public_key: input.signing_public_key,
            commitment: commitment
        }
    }
}

// Witness struct for account notes
struct Witness {
    alias_hash: Field, 
    account_public_key: [Field; 2], 
    signing_public_key: [Field; 2],
}