// ********************* Account Notes *********************

use dep::std;

// Witness struct for account notes
struct AccountWitness {
    alias_hash: Field, 
    new_account_public_key: [Field; 2], 
    signing_public_key: [Field; 2],
}

// Account struct for account notes
struct Account {
    alias_hash: Field, 
    new_account_public_key: [Field; 2], 
    signing_public_key: [Field; 2],
    commitment: Field,
}

impl Account {
    fn new(
        input: AccountWitness
    ) -> Account {
        let commitment = std::hash::pedersen([
            input.alias_hash, 
            input.new_account_public_key[0], 
            input.new_account_public_key[1], 
            input.signing_public_key[0], 
            input.signing_public_key[1],
        ])[0];
        Account {
            alias_hash: input.alias_hash,
            new_account_public_key: input.new_account_public_key,
            signing_public_key: input.signing_public_key,
            commitment: commitment,
        }
    }
}