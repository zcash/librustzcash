use pairing::{Engine, Field};
use bellman::{ConstraintSystem, SynthesisError, Circuit, LinearCombination};
use circuit::boolean::{
    AllocatedBit,
    Boolean
};
use circuit::multipack::pack_into_inputs;

mod prfs;
mod commitment;
mod input;
mod output;

use self::input::*;
use self::output::*;

pub const TREE_DEPTH: usize = 29;

pub struct SpendingKey(pub [u8; 32]);
pub struct PayingKey(pub [u8; 32]);
pub struct UniqueRandomness(pub [u8; 32]);
pub struct CommitmentRandomness(pub [u8; 32]);

pub struct JoinSplit {
    pub vpub_old: Option<u64>,
    pub vpub_new: Option<u64>,
    pub h_sig: Option<[u8; 32]>,
    pub phi: Option<[u8; 32]>,
    pub inputs: Vec<JSInput>,
    pub outputs: Vec<JSOutput>,
    pub rt: Option<[u8; 32]>,
}

pub struct JSInput {
    pub value: Option<u64>,
    pub a_sk: Option<SpendingKey>,
    pub rho: Option<UniqueRandomness>,
    pub r: Option<CommitmentRandomness>,
    pub auth_path: [Option<([u8; 32], bool)>; TREE_DEPTH]
}

pub struct JSOutput {
    pub value: Option<u64>,
    pub a_pk: Option<PayingKey>,
    pub r: Option<CommitmentRandomness>
}

impl<E: Engine> Circuit<E> for JoinSplit {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        assert_eq!(self.inputs.len(), 2);
        assert_eq!(self.outputs.len(), 2);

        // vpub_old is the value entering the
        // JoinSplit from the "outside" value
        // pool
        let vpub_old = NoteValue::new(
            cs.namespace(|| "vpub_old"),
            self.vpub_old
        )?;

        // vpub_new is the value leaving the
        // JoinSplit into the "outside" value
        // pool
        let vpub_new = NoteValue::new(
            cs.namespace(|| "vpub_new"),
            self.vpub_new
        )?;

        // The left hand side of the balance equation
        // vpub_old + inputs[0].value + inputs[1].value
        let mut lhs = vpub_old.lc();

        // The right hand side of the balance equation
        // vpub_old + inputs[0].value + inputs[1].value
        let mut rhs = vpub_new.lc();

        // Witness rt (merkle tree root)
        let rt = witness_u256(
            cs.namespace(|| "rt"),
            self.rt.as_ref().map(|v| &v[..])
        ).unwrap();

        // Witness h_sig
        let h_sig = witness_u256(
            cs.namespace(|| "h_sig"),
            self.h_sig.as_ref().map(|v| &v[..])
        ).unwrap();

        // Witness phi
        let phi = witness_u252(
            cs.namespace(|| "phi"),
            self.phi.as_ref().map(|v| &v[..])
        ).unwrap();

        let mut input_notes = vec![];
        let mut lhs_total = self.vpub_old;

        // Iterate over the JoinSplit inputs
        for (i, input) in self.inputs.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("input {}", i));

            // Accumulate the value of the left hand side
            if let Some(value) = input.value {
                lhs_total = lhs_total.map(|v| v.wrapping_add(value));
            }

            // Allocate the value of the note
            let value = NoteValue::new(
                cs.namespace(|| "value"),
                input.value
            )?;

            // Compute the nonce (for PRF inputs) which is false
            // for the first input, and true for the second input.
            let nonce = match i {
                0 => false,
                1 => true,
                _ => unreachable!()
            };

            // Perform input note computations
            input_notes.push(InputNote::compute(
                cs.namespace(|| "note"),
                input.a_sk,
                input.rho,
                input.r,
                &value,
                &h_sig,
                nonce,
                input.auth_path,
                &rt
            )?);

            // Add the note value to the left hand side of
            // the balance equation
            lhs = lhs + &value.lc();
        }

        // Rebind lhs so that it isn't mutable anymore
        let lhs = lhs;

        // See zcash/zcash/issues/854
        {
            // Expected sum of the left hand side of the balance
            // equation, expressed as a 64-bit unsigned integer
            let lhs_total = NoteValue::new(
                cs.namespace(|| "total value of left hand side"),
                lhs_total
            )?;

            // Enforce that the left hand side can be expressed as a 64-bit
            // integer
            cs.enforce(
                || "left hand side can be expressed as a 64-bit unsigned integer",
                |_| lhs.clone(),
                |lc| lc + CS::one(),
                |_| lhs_total.lc()
            );
        }

        let mut output_notes = vec![];

        // Iterate over the JoinSplit outputs
        for (i, output) in self.outputs.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("output {}", i));

            let value = NoteValue::new(
                cs.namespace(|| "value"),
                output.value
            )?;

            // Compute the nonce (for PRF inputs) which is false
            // for the first output, and true for the second output.
            let nonce = match i {
                0 => false,
                1 => true,
                _ => unreachable!()
            };

            // Perform output note computations
            output_notes.push(OutputNote::compute(
                cs.namespace(|| "note"),
                output.a_pk,
                &value,
                output.r,
                &phi,
                &h_sig,
                nonce
            )?);

            // Add the note value to the right hand side of
            // the balance equation
            rhs = rhs + &value.lc();
        }

        // Enforce that balance is equal
        cs.enforce(
            || "balance equation",
            |_| lhs.clone(),
            |lc| lc + CS::one(),
            |_| rhs
        );

        let mut public_inputs = vec![];
        public_inputs.extend(rt);
        public_inputs.extend(h_sig);

        for note in input_notes {
            public_inputs.extend(note.nf);
            public_inputs.extend(note.mac);
        }

        for note in output_notes {
            public_inputs.extend(note.cm);
        }

        public_inputs.extend(vpub_old.bits_le());
        public_inputs.extend(vpub_new.bits_le());

        pack_into_inputs(cs.namespace(|| "input packing"), &public_inputs)
    }
}

pub struct NoteValue {
    value: Option<u64>,
    // Least significant digit first
    bits: Vec<AllocatedBit>
}

impl NoteValue {
    fn new<E, CS>(
        mut cs: CS,
        value: Option<u64>
    ) -> Result<NoteValue, SynthesisError>
        where E: Engine, CS: ConstraintSystem<E>,
    {
        let mut values;
        match value {
            Some(mut val) => {
                values = vec![];
                for _ in 0..64 {
                    values.push(Some(val & 1 == 1));
                    val >>= 1;
                }
            },
            None => {
                values = vec![None; 64];
            }
        }

        let mut bits = vec![];
        for (i, value) in values.into_iter().enumerate() {
            bits.push(
                AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    value
                )?
            );
        }

        Ok(NoteValue {
            value: value,
            bits: bits
        })
    }

    /// Encodes the bits of the value into little-endian
    /// byte order.
    fn bits_le(&self) -> Vec<Boolean> {
        self.bits.chunks(8)
                 .flat_map(|v| v.iter().rev())
                 .cloned()
                 .map(|e| Boolean::from(e))
                 .collect()
    }

    /// Computes this value as a linear combination of
    /// its bits.
    fn lc<E: Engine>(&self) -> LinearCombination<E> {
        let mut tmp = LinearCombination::zero();

        let mut coeff = E::Fr::one();
        for b in &self.bits {
            tmp = tmp + (coeff, b.get_variable());
            coeff.double();
        }

        tmp
    }

    fn get_value(&self) -> Option<u64> {
        self.value
    }
}

/// Witnesses some bytes in the constraint system,
/// skipping the first `skip_bits`.
fn witness_bits<E, CS>(
    mut cs: CS,
    value: Option<&[u8]>,
    num_bits: usize,
    skip_bits: usize
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    let bit_values = if let Some(value) = value {
        let mut tmp = vec![];
        for b in value.iter()
                      .flat_map(|&m| (0..8).rev().map(move |i| m >> i & 1 == 1))
                      .skip(skip_bits)
        {
            tmp.push(Some(b));
        }
        tmp
    } else {
        vec![None; num_bits]
    };
    assert_eq!(bit_values.len(), num_bits);

    let mut bits = vec![];

    for (i, value) in bit_values.into_iter().enumerate() {
        bits.push(Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| format!("bit {}", i)),
            value
        )?));
    }

    Ok(bits)
}

fn witness_u256<E, CS>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 256, 0)
}

fn witness_u252<E, CS>(
    cs: CS,
    value: Option<&[u8]>,
) -> Result<Vec<Boolean>, SynthesisError>
    where E: Engine, CS: ConstraintSystem<E>,
{
    witness_bits(cs, value, 252, 4)
}

#[test]
fn test_sprout_constraints() {
    use pairing::bls12_381::{Bls12};
    use ::circuit::test::*;

    use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian};

    let mut cs = TestConstraintSystem::<Bls12>::new();

    let test_vector = hex!("0da71d04d1a5fa649239c73de9c516d2f54958f0f92118113671633872346a31d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd2591e6b61f9f84d6f70fc34838a5a898df04c9a13f1fbfc2b1433de718046efd7d61d20c0db2a74998c50eb7ba6534f6d410efc27c4bb88acb0222c7906ea28a327b51120c92b32db42f42e2bf0a59df9055be5c669d3242df45357659b75ae2c27a76f502008f279618616bcdd4eadc9c7a9062691a59b43b07e2c1e237f17bd189cd6a8fe20925e6d474a5d8d3004f29da0dd78d30ae3824ce79dfe4934bb29ec3afaf3d5212058a2753dade103cecbcda50b5ebfce31e12d41d5841dcc95620f7b3d50a1b9a120f30cc836b9f71b4e7ee3c72b1fd253268af9a27e9d7291a23d02821b21ddfd1620bb23a9bba56de57cb284b0d2b01c642cf79c9a5563f0067a21292412145bd78a20671546e26b1da1af754531e26d8a6a51073a57ddd72dc472efb43fcb257cffff200323f2850bf3444f4b4c5c09a6057ec7169190f45acb9e46984ab3dfcec4f06a205145b1b055c2df02b95675e3797b91de1b846d25003c0a803d08900728f2cd6a2011aa0b4ad29b13b057a31619d6500d636cd735cdd07d811ea265ec4bcbbbd05820bab5800972a16c2c22530c66066d0a5867e987bed21a6d5a450b683cf1cfd70920bdcdb3293188c9807d808267018684cfece07ac35a42c00f2c79b4003825305d20507e0dae81cbfbe457fd370ef1ca4201c2b6401083ddab440e4a038dc1e358c4205dad844ab9466b70f745137195ca221b48f346abd145fb5efc23a8b4ba508022207333dbffbd11f09247a2b33a013ec4c4342029d851e22ba485d4461851370c152089a434ae1febd7687eceea21d07f20a2512449d08ce2eee55871cdb9d46c123320c22d8f0b5e4056e5f318ba22091cc07db5694fbeb5e87ef0d7e2c57ca352359e201ddddabc2caa2de9eff9e18c8c5a39406d7936e889bc16cfabb144f5c002268220a083450c1ba2a3a7be76fad9d13bc37be4bf83bd3e59fc375a36ba62dc620298208c085674249b43da1b9a31a0e820e81e75f342807b03b6b9e64983217bc2b38e2040460fa6bc692a06f47521a6725a547c028a6a240d8409f165e63cb54da2d23f203f909b8ce3d7ffd8a5b30908f605a03b0db85169558ddc1da7bbbcc9b09fd325200109ecc0722659ff83450b8f7b8846e67b2859f33c30d9b7acd5bf39cae54e312026b0052694fc42fdff93e6fb5a71d38c3dd7dc5b6ad710eb048c660233137fab203f0a406181105968fdaee30679e3273c66b72bf9a7f5debbf3b5a0a26e359f9220dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c20da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d82000000000000000000000000000000000000000000000000000000000000000000000000000000000788445f3120af7846f3625a24ce18250905d9007150e276795271f2572293b20000000000000000082dbed5b3b4048851fb78feb4601ff03be53d6a4b93e97599f4fb6a23db710c41d7193cecb40f4601fc2214b14e0435646a61f0ad1eced90d69911c29850661c074dfe1a712c29b36441a71969c34c7ef1d1c6ec89dfe3c7ceb647c4a2c891061d20c0db2a74998c50eb7ba6534f6d410efc27c4bb88acb0222c7906ea28a327b51120c92b32db42f42e2bf0a59df9055be5c669d3242df45357659b75ae2c27a76f502008f279618616bcdd4eadc9c7a9062691a59b43b07e2c1e237f17bd189cd6a8fe20925e6d474a5d8d3004f29da0dd78d30ae3824ce79dfe4934bb29ec3afaf3d5212058a2753dade103cecbcda50b5ebfce31e12d41d5841dcc95620f7b3d50a1b9a120f30cc836b9f71b4e7ee3c72b1fd253268af9a27e9d7291a23d02821b21ddfd1620bb23a9bba56de57cb284b0d2b01c642cf79c9a5563f0067a21292412145bd78a20671546e26b1da1af754531e26d8a6a51073a57ddd72dc472efb43fcb257cffff200323f2850bf3444f4b4c5c09a6057ec7169190f45acb9e46984ab3dfcec4f06a205145b1b055c2df02b95675e3797b91de1b846d25003c0a803d08900728f2cd6a2011aa0b4ad29b13b057a31619d6500d636cd735cdd07d811ea265ec4bcbbbd05820bab5800972a16c2c22530c66066d0a5867e987bed21a6d5a450b683cf1cfd70920bdcdb3293188c9807d808267018684cfece07ac35a42c00f2c79b4003825305d20507e0dae81cbfbe457fd370ef1ca4201c2b6401083ddab440e4a038dc1e358c4205dad844ab9466b70f745137195ca221b48f346abd145fb5efc23a8b4ba508022207333dbffbd11f09247a2b33a013ec4c4342029d851e22ba485d4461851370c152089a434ae1febd7687eceea21d07f20a2512449d08ce2eee55871cdb9d46c123320c22d8f0b5e4056e5f318ba22091cc07db5694fbeb5e87ef0d7e2c57ca352359e201ddddabc2caa2de9eff9e18c8c5a39406d7936e889bc16cfabb144f5c002268220a083450c1ba2a3a7be76fad9d13bc37be4bf83bd3e59fc375a36ba62dc620298208c085674249b43da1b9a31a0e820e81e75f342807b03b6b9e64983217bc2b38e2040460fa6bc692a06f47521a6725a547c028a6a240d8409f165e63cb54da2d23f203f909b8ce3d7ffd8a5b30908f605a03b0db85169558ddc1da7bbbcc9b09fd325200109ecc0722659ff83450b8f7b8846e67b2859f33c30d9b7acd5bf39cae54e312026b0052694fc42fdff93e6fb5a71d38c3dd7dc5b6ad710eb048c660233137fab203f0a406181105968fdaee30679e3273c66b72bf9a7f5debbf3b5a0a26e359f9220dc766fab492ccf3d1e49d4f374b5235fa56506aac2224d39f943fcd49202974c20da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8200000000000000000000000000000000000000000000000000000000000000000000000000000000074a32261e497b4a90a786b3c86593d1538d1cebfca0c558c1f00a15cd1726df000000000000000002ce6a5a2b90f0d84f0abefe276a9306b30e4efc3cc4c1a3d2461d5fe5aef48491e1a35d1e0c1b8bd124fec233b0e5e6446b33b998b5c055161239e740459581606241488b3b9a0cc5ce17f7c08a2862b3cb64328de743eef32215210c57d657f037ae0cb7390166b0b327db98b06eb8b018a948a952e9a2b1772552f60738be200000000000000004f04a021600858d805c9ec555dbfe37eb7680bec562848e346495989e99617a691bff31ffb4ae2009e3106a8e23e5ed365b6aa05f27ce43c709dc9977a71678e3853150ec9e5782948eae5cd6c6b92f9e52e9e7f340dbf9ed50a4ea91456150a00000000000000006669719d78ac8126c22afb145d1bc7bd4c35fcb0363ffd1cd42e01a67abb4339f84507f6918b18c984574a9c4ee5a0fa192fb64a26054dfec97a487ee3a0b1720000000000000000000000000000000026c601601d75c28aaa786fb4f3b97fdb21f2d6fd5ff7a1ddf698f262f9be2e98d0184d08ee099711504094a639f4e65fd4c11e003b6ef9547465cec7452ad06435999ba8a4eb6018747ed1cac7e6dbda8260d4d4467572a7e5440d4337eeb0d994c1aca55e1dfe0b4dd7664ee652c6c4ffbdf9f284f3932fdc89b1aef23559fe4fa50b383248c24e50b8193406a97e6d709a6a9d076656b77b000b3ef178084da307423830ffe8afffdf18656cf5ebc197c5e140a952bebe8d52fbb5474fb30a");
    let mut test_vector = &test_vector[..];

    fn get_u256<R: ReadBytesExt>(mut reader: R) -> [u8; 32] {
        let mut result = [0u8; 32];

        for i in 0..32 {
            result[i] = reader.read_u8().unwrap();
        }

        result
    }

    let phi = Some(get_u256(&mut test_vector));
    let rt = Some(get_u256(&mut test_vector));
    let h_sig = Some(get_u256(&mut test_vector));

    let mut inputs = vec![];
    for _ in 0..2 {
        test_vector.read_u8().unwrap();

        let mut auth_path = [None; TREE_DEPTH];
        for i in (0..TREE_DEPTH).rev() {
            test_vector.read_u8().unwrap();

            let sibling = get_u256(&mut test_vector);

            auth_path[i] = Some((sibling, false));
        }
        let mut position = test_vector.read_u64::<LittleEndian>().unwrap();
        for i in (0..TREE_DEPTH).rev() {
            auth_path[i].as_mut().map(|p| {
                p.1 = (position & 1) == 1
            });

            position >>= 1;
        }

        // a_pk
        let _ = Some(SpendingKey(get_u256(&mut test_vector)));
        let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
        let rho = Some(UniqueRandomness(get_u256(&mut test_vector)));
        let r = Some(CommitmentRandomness(get_u256(&mut test_vector)));
        let a_sk = Some(SpendingKey(get_u256(&mut test_vector)));

        inputs.push(
            JSInput {
                value: value,
                a_sk: a_sk,
                rho: rho,
                r: r,
                auth_path: auth_path
            }
        );
    }

    let mut outputs = vec![];

    for _ in 0..2 {
        let a_pk = Some(PayingKey(get_u256(&mut test_vector)));
        let value = Some(test_vector.read_u64::<LittleEndian>().unwrap());
        get_u256(&mut test_vector);
        let r = Some(CommitmentRandomness(get_u256(&mut test_vector)));

        outputs.push(
            JSOutput {
                value: value,
                a_pk: a_pk,
                r: r
            }
        );
    }

    let vpub_old = Some(test_vector.read_u64::<LittleEndian>().unwrap());
    let vpub_new = Some(test_vector.read_u64::<LittleEndian>().unwrap());

    let nf1 = get_u256(&mut test_vector);
    let nf2 = get_u256(&mut test_vector);

    let cm1 = get_u256(&mut test_vector);
    let cm2 = get_u256(&mut test_vector);

    let mac1 = get_u256(&mut test_vector);
    let mac2 = get_u256(&mut test_vector);

    assert_eq!(test_vector.len(), 0);

    let js = JoinSplit {
        vpub_old: vpub_old,
        vpub_new: vpub_new,
        h_sig: h_sig,
        phi: phi,
        inputs: inputs,
        outputs: outputs,
        rt: rt
    };

    js.synthesize(&mut cs).unwrap();

    if let Some(s) = cs.which_is_unsatisfied() {
        panic!("{:?}", s);
    }
    assert!(cs.is_satisfied());
    assert_eq!(cs.num_constraints(), 1989085);
    assert_eq!(cs.num_inputs(), 10);
    assert_eq!(cs.hash(), "1a228d3c6377130d1778c7885811dc8b8864049cb5af8aff7e6cd46c5bc4b84c");

    let mut expected_inputs = vec![];
    expected_inputs.extend(rt.unwrap().to_vec());
    expected_inputs.extend(h_sig.unwrap().to_vec());
    expected_inputs.extend(nf1.to_vec());
    expected_inputs.extend(mac1.to_vec());
    expected_inputs.extend(nf2.to_vec());
    expected_inputs.extend(mac2.to_vec());
    expected_inputs.extend(cm1.to_vec());
    expected_inputs.extend(cm2.to_vec());
    expected_inputs.write_u64::<LittleEndian>(vpub_old.unwrap()).unwrap();
    expected_inputs.write_u64::<LittleEndian>(vpub_new.unwrap()).unwrap();

    use circuit::multipack;

    let expected_inputs = multipack::bytes_to_bits(&expected_inputs);
    let expected_inputs = multipack::compute_multipacking::<Bls12>(&expected_inputs);

    assert!(cs.verify(&expected_inputs));
}
