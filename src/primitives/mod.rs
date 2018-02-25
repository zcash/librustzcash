use pedersen_hash::{
    pedersen_hash,
    Personalization
};

use byteorder::{
    BigEndian,
    ByteOrder
};

use jubjub::{
    JubjubEngine,
    JubjubParams,
    edwards,
    PrimeOrder,
    FixedGenerators
};

pub struct Note<E: JubjubEngine> {
    /// The value of the note
    pub value: u64,
    /// The diversified base of the address, GH(d)
    pub g_d: edwards::Point<E, PrimeOrder>,
    /// The public key of the address, g_d^ivk
    pub pk_d: edwards::Point<E, PrimeOrder>,
    /// The commitment randomness
    pub r: E::Fs
}

impl<E: JubjubEngine> Note<E> {
    /// Computes the note commitment
    pub fn cm(&self, params: &E::Params) -> E::Fr
    {
        // Calculate the note contents, as bytes
        let mut note_contents = vec![];

        // Write the value in big endian
        BigEndian::write_u64(&mut note_contents, self.value);

        // Write g_d
        self.g_d.write(&mut note_contents).unwrap();

        // Write pk_d
        self.pk_d.write(&mut note_contents).unwrap();

        // Compute the Pedersen hash of the note contents
        let hash_of_contents = pedersen_hash(
            Personalization::NoteCommitment,
            note_contents.into_iter()
                         .flat_map(|byte| {
                            (0..8).rev().map(move |i| ((byte >> i) & 1) == 1)
                         }),
            params
        );

        // Compute final commitment
        let cm = params.generator(FixedGenerators::NoteCommitmentRandomness)
                       .mul(self.r, params)
                       .add(&hash_of_contents, params);

        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the x-coordinate is an injective encoding.
        cm.into_xy().0
    }
}
