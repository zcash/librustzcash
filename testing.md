# Testing DSL

<!--toc:start-->
- [Testing DSL](#testing-dsl)
  - [Analysis of prior art](#analysis-of-prior-art)
    - [Sandbox](#sandbox)
    - [Existing test functions](#existing-test-functions)
    - [High level steps present in (nearly) all test functions](#high-level-steps-present-in-nearly-all-test-functions)
<!--toc:end-->

The following is a step-by-step analysis of each test function. I'm using this
analysis to inform what abstractions to employ in the testing DSL.

## TODO

### Kris

* Fee rule and change strategy should probably be part of the setup at this point; we basically only want to consider ZIP 317 fees.
* In many cases, the proposal / creation / scan don't need to be separate operations, one function should do all 3.

### str4d

My ideal here is that the test DSL can express three high-level operations:
* [x] Specify the initial state.
* Verify the current state.
* [x] Apply a state transition.
and the second/third are repeated and interleaved for as many steps as it takes to test the functionality.

## Notes

- [ ] In `spend_everything_multi_step_with_marginal_notes_proposed_transfer`, after generating
  a block with a note of value with the zip317 marginal fee, my test DSL expects that the total
  balance includes that marginal fee, but it's not there.
* When attempting to use a very granular scenario encoding where each step has inputs and outputs,
  I ran into the obvious problem where the input of later steps depend on the output of earlier
  steps, but of course if you're building the scenario before running it, you don't have that input
  yet.
  This means I would have to have input wrapped in some "it's not here yet but it will be later"
  type (like `Arc<Mutex<Option<_>>>`), but that's obviously very ugly.
  Maybe it's ultimately what we need, I don't know.
  I've saved that work in the `chore/pool-testing-dsl-encoded-input-output` branch.

## Sandbox

This section is a sandbox to gather code present in each test function (listed below) to analyze
and determine an appropriate abstraction.

The current effort is about discovering an abstraction for "Add Funds", which is described
below in the [high level steps](#high-level-steps-present-in-nearly-all-test-functions).

### send_single_step_proposed_transfer
```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```

### zip_315_confirmations_test_steps

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, address_type, starting_balance);
st.scan_cached_blocks(h, 1);
```
### spend_max_spendable_single_step_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

let confirmation_policy = ConfirmationsPolicy::new_symmetrical(
    NonZeroU32::new(2).expect("2 is not zero"),
    #[cfg(feature = "transparent-inputs")]
    false,
);
st.generate_empty_block();
st.generate_empty_block();
st.generate_empty_block();

st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

st.scan_cached_blocks(h, 5);
```
### spend_everything_single_step_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### fails_to_send_max_spendable_to_transparent_with_memo

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### spend_everything_proposal_fails_when_unconfirmed_funds_present

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

st.generate_empty_block();
st.generate_empty_block();
let later_on_value = Zatoshis::const_from_u64(123456);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, later_on_value);
st.scan_cached_blocks(h1, 4);
```
### send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

st.generate_empty_block();
st.generate_empty_block();
let later_on_value = Zatoshis::const_from_u64(123456);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, later_on_value);
st.scan_cached_blocks(h1, 4);
```

### spend_everything_multi_step_single_note_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(100000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### spend_everything_multi_step_many_notes_proposed_transfer

```rust
// Add funds to the wallet in multiple notes
let number_of_notes = 3u64;
let note_value = Zatoshis::const_from_u64(100000);
let value = (note_value * number_of_notes).unwrap();

for _ in 0..number_of_notes {
    add_funds(&mut st, note_value);
}
```
### spend_everything_multi_step_with_marginal_notes_proposed_transfer

```rust
// Add funds to the wallet in multiple notes
let number_of_notes = 10u64;
let note_value = Zatoshis::const_from_u64(100000);
let non_marginal_notes_value =
    (note_value * number_of_notes).expect("sum of notes should not fail.");

for _ in 0..number_of_notes {
    add_funds(&mut st, note_value);
    add_funds(&mut st, zip317::MARGINAL_FEE);
}
```
### send_with_multiple_change_outputs

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(650_0000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### send_multi_step_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(100000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### spend_all_funds_single_step_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(60000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### spend_all_funds_multi_step_proposed_transfer

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(100000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### proposal_fails_if_not_all_ephemeral_outputs_consumed

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(100000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### create_to_address_fails_on_incorrect_usk

```rust
// No funds added in this function
```
### proposal_fails_with_no_blocks

```rust
// No funds added in this function
```
### spend_fails_on_unverified_notes

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(50000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h1, 1);
```

```rust
// Add more funds to the wallet
let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h2, 1);
```
### spend_fails_on_locked_notes

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(50000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h1, 1);
```
### ovk_policy_prevents_recovery_from_chain

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(50000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h1, 1);
```
### spend_succeeds_to_t_addr_zero_change

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(70000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### change_note_spends_succeed

```rust
// Add funds to the wallet in a single note owned by the internal spending key
let value = Zatoshis::const_from_u64(70000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
st.scan_cached_blocks(h, 1);
```
### external_address_change_spends_detected_in_restore_from_seed

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::from_u64(100000).unwrap();
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h, 1);
```
### zip317_spend

```rust
// Add funds to the wallet
let (h1, _, _) = st.generate_next_block(
    &dfvk,
    AddressType::Internal,
    Zatoshis::const_from_u64(50000),
);

// Add 10 dust notes to the wallet
for _ in 1..=10 {
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(1000),
    );
}

st.scan_cached_blocks(h1, 11);
```
### shield_transparent

```rust
// Add funds to the wallet in a single note
let value = Zatoshis::const_from_u64(50000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
st.scan_cached_blocks(h, 1);
```
### birthday_in_anchor_shard

```rust
// Generate blocks with and without value for the wallet
let not_our_value = Zatoshis::const_from_u64(10000);
let not_our_key = T::random_fvk(st.rng_mut());
let (initial_height, _, _) =
    st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
for _ in 1..9 {
    st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
}

// Now, generate a block that belongs to our wallet
let (received_tx_height, _, _) = st.generate_next_block(
    &T::test_account_fvk(&st),
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(500000),
);

// Generate some more blocks to get above our anchor height
for _ in 0..15 {
    st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
}
```
### checkpoint_gaps

```rust
// Generate a block with funds belonging to our wallet.
st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(500000),
);
st.scan_cached_blocks(account.birthday().height(), 1);

// Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
// belong to us so that we can get a checkpoint in the tree.
let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
let not_our_value = Zatoshis::const_from_u64(10000);
st.generate_block_at(
    account.birthday().height() + 10,
    BlockHash([0; 32]),
    &[FakeCompactOutput::new(
        &not_our_key,
        AddressType::DefaultExternal,
        not_our_value,
    )],
    st.latest_cached_block().unwrap().sapling_end_size(),
    st.latest_cached_block().unwrap().orchard_end_size(),
    false,
);

// Scan the block
st.scan_cached_blocks(account.birthday().height() + 10, 1);
```
### pool_crossing_required

```rust
// Add funds to the wallet in a single note
let note_value = Zatoshis::const_from_u64(350000);
st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.scan_cached_blocks(account.birthday().height(), 2);
```
### fully_funded_fully_private

```rust
// Add funds to the wallet in multiple notes
let note_value = Zatoshis::const_from_u64(350000);
st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
st.scan_cached_blocks(account.birthday().height(), 2);
```
### fully_funded_send_to_t

```rust
// Add funds to the wallet in multiple notes
let note_value = Zatoshis::const_from_u64(350000);
st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
st.scan_cached_blocks(account.birthday().height(), 2);
```
### multi_pool_checkpoint

```rust
// Add funds to the wallet in multiple notes
let note_value = Zatoshis::const_from_u64(500000);
let (start_height, _, _) =
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
let scanned = st.scan_cached_blocks(start_height, 3);
```
### multi_pool_checkpoints_with_pruning

```rust
// Generate blocks with and without value for the wallet
let note_value = Zatoshis::const_from_u64(10000);
// Generate 100 P0 blocks, then 100 P1 blocks, then another 100 P0 blocks.
for _ in 0..10 {
    for _ in 0..10 {
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    }
    for _ in 0..10 {
        st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    }
}
st.scan_cached_blocks(account.birthday().height(), 200);
for _ in 0..100 {
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
}
st.scan_cached_blocks(account.birthday().height() + 200, 200);
```
### valid_chain_states

```rust
// Create a fake CompactBlock sending value to the address
let (h1, _, _) = st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(5),
);

// Scan the cache
st.scan_cached_blocks(h1, 1);

// Create a second fake CompactBlock sending more value to the address
let (h2, _, _) = st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(7),
);

// Scanning should detect no inconsistencies
st.scan_cached_blocks(h2, 1);
```
### invalid_chain_cache_disconnected

```rust
// Create some fake CompactBlocks
let (h, _, _) = st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(5),
);
let (last_contiguous_height, _, _) = st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(7),
);

// Scanning the cache should find no inconsistencies
st.scan_cached_blocks(h, 2);

// Create more fake CompactBlocks that don't connect to the scanned ones
let disconnect_height = last_contiguous_height + 1;
st.generate_block_at(
    disconnect_height,
    BlockHash([1; 32]),
    &[FakeCompactOutput::new(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(8),
    )],
    2,
    2,
    true,
);
st.generate_next_block(
    &dfvk,
    AddressType::DefaultExternal,
    Zatoshis::const_from_u64(3),
);
```
### data_db_truncation

```rust
// Create fake CompactBlocks sending value to the address
let value = Zatoshis::const_from_u64(50000);
let value2 = Zatoshis::const_from_u64(70000);
let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

// Scan the cache
st.scan_cached_blocks(h, 2);
```
### reorg_to_checkpoint

```rust
// Create a sequence of blocks to serve as the foundation of our chain state.
let p0_fvk = T::random_fvk(st.rng_mut());
let gen_random_block = |st: &mut TestState<C, Dsf::DataStore, LocalNetwork>,
                        output_count: usize| {
    let fake_outputs =
        std::iter::repeat_with(|| FakeCompactOutput::random(st.rng_mut(), p0_fvk.clone()))
            .take(output_count)
            .collect::<Vec<_>>();
    st.generate_next_block_multi(&fake_outputs[..]);
    output_count
};

// The stable portion of the tree will contain 20 notes.
for _ in 0..10 {
    gen_random_block(&mut st, 4);
}

// We will reorg to this height.
let reorg_height = account.birthday().height() + 4;
let reorg_position = Position::from(19);

// Scan the first 5 blocks. The last block in this sequence will be where we simulate a
// reorg.
st.scan_cached_blocks(account.birthday().height(), 5);
```
### scan_cached_blocks_allows_blocks_out_of_order

```rust
// Create blocks with value for the wallet
let value = Zatoshis::const_from_u64(50000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
st.scan_cached_blocks(h1, 1);
assert_eq!(st.get_total_balance(account.id()), value);

// Create blocks to reach height + 2
let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

// Scan the later block first
st.scan_cached_blocks(h3, 1);

// Now scan the block of height height + 1
st.scan_cached_blocks(h2, 1);
assert_eq!(
    st.get_total_balance(account.id()),
    Zatoshis::const_from_u64(150_000)
);
```
### scan_cached_blocks_finds_received_notes

```rust
// Create a fake CompactBlock sending value to the address
let value = Zatoshis::const_from_u64(50000);
let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

// Scan the cache
let summary = st.scan_cached_blocks(h1, 1);
assert_eq!(summary.scanned_range().start, h1);
assert_eq!(summary.scanned_range().end, h1 + 1);
assert_eq!(T::received_note_count(&summary), 1);

// Account balance should reflect the received note
assert_eq!(st.get_total_balance(account.id()), value);

// Create a second fake CompactBlock sending more value to the address
let value2 = Zatoshis::const_from_u64(70000);
let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

// Scan the cache again
let summary = st.scan_cached_blocks(h2, 1);
assert_eq!(summary.scanned_range().start, h2);
assert_eq!(summary.scanned_range().end, h2 + 1);
assert_eq!(T::received_note_count(&summary), 1);

// Account balance should reflect both received notes
assert_eq!(
    st.get_total_balance(account.id()),
    (value + value2).unwrap()
);
```
### scan_cached_blocks_finds_change_notes

```rust
// Create a fake CompactBlock sending value to the address
let value = Zatoshis::const_from_u64(50000);
let (received_height, _, nf) =
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

// Scan the cache
st.scan_cached_blocks(received_height, 1);

// Account balance should reflect the received note
assert_eq!(st.get_total_balance(account.id()), value);

// Create a second fake CompactBlock spending value from the address
let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
let to2 = T::fvk_default_address(&not_our_key);
let value2 = Zatoshis::const_from_u64(20000);
let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

// Scan the cache again
st.scan_cached_blocks(spent_height, 1);

// Account balance should equal the change
assert_eq!(
    st.get_total_balance(account.id()),
    (value - value2).unwrap()
);
```
### scan_cached_blocks_detects_spends_out_of_order

```rust
// Create a fake CompactBlock sending value to the address
let value = Zatoshis::const_from_u64(50000);
let (received_height, _, nf) =
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

// Create a second fake CompactBlock spending value from the address
let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
let to2 = T::fvk_default_address(&not_our_key);
let value2 = Zatoshis::const_from_u64(20000);
let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

// Scan the spending block first.
st.scan_cached_blocks(spent_height, 1);

// Account balance should equal the change
assert_eq!(
    st.get_total_balance(account.id()),
    (value - value2).unwrap()
);

// Now scan the block in which we received the note that was spent.
st.scan_cached_blocks(received_height, 1);

// Account balance should be the same.
assert_eq!(
    st.get_total_balance(account.id()),
    (value - value2).unwrap()
);
```
### metadata_queries_exclude_unwanted_notes

```rust
// Create blocks with value for the wallet
let value = Zatoshis::const_from_u64(100_0000);
let (h0, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
let mut note_values = vec![value];
for i in 2..=10 {
    let value = Zatoshis::const_from_u64(i * 100_0000);
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    note_values.push(value);
}
st.scan_cached_blocks(h0, 10);
let target_height = TargetHeight::from(h0 + 10);
```
### pczt_single_step

```rust
// Add funds to the wallet in a single note
let note_value = Zatoshis::const_from_u64(350000);
st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
st.scan_cached_blocks(account.birthday().height(), 1);
```
### wallet_recovery_computes_fees

```rust
// Get some funds in the source account
let note_value = Zatoshis::const_from_u64(350000);
st.generate_next_block(&from, AddressType::DefaultExternal, note_value);
st.generate_next_block(&from, AddressType::DefaultExternal, note_value);
st.scan_cached_blocks(source_account.birthday().height(), 2);
```
### receive_two_notes_with_same_value

```rust
// Add funds to the wallet in two identical notes
let value = Zatoshis::const_from_u64(60000);
let outputs = [
    FakeCompactOutput::new(&dfvk, AddressType::DefaultExternal, value),
    FakeCompactOutput::new(&dfvk, AddressType::DefaultExternal, value),
];
let total_value = (value + value).unwrap;

// `st.generate_next_block` with multiple outputs.
let pre_activation_block = CachedBlock::none(st.sapling_activation_height() - 1);
let prior_cached_block = st.latest_cached_block().unwrap_or(&pre_activation_block);
let h = prior_cached_block.height() + 1;
st.generate_block_at(
    h,
    prior_cached_block.chain_state.block_hash(),
    &outputs,
    prior_cached_block.sapling_end_size,
    prior_cached_block.orchard_end_size,
    false,
);

st.scan_cached_blocks(h, 1);
assert_eq!(
    st.wallet()
        .block_max_scanned()
        .unwrap()
        .unwrap()
        .block_height(),
    h
);
```

## Existing test functions

This is a list of the test functions that the DSL will pertain to.

```yaml
- send_single_step_proposed_transfer
- zip_315_confirmations_test_steps
- spend_max_spendable_single_step_proposed_transfer
- spend_everything_single_step_proposed_transfer
- fails_to_send_max_spendable_to_transparent_with_memo
- spend_everything_proposal_fails_when_unconfirmed_funds_present
- send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present
- spend_everything_multi_step_single_note_proposed_transfer
- spend_everything_multi_step_many_notes_proposed_transfer
- spend_everything_multi_step_with_marginal_notes_proposed_transfer
- send_with_multiple_change_outputs
- send_multi_step_proposed_transfer
- spend_all_funds_single_step_proposed_transfer
- spend_all_funds_multi_step_proposed_transfer
- proposal_fails_if_not_all_ephemeral_outputs_consumed
- create_to_address_fails_on_incorrect_usk
- proposal_fails_with_no_blocks
- spend_fails_on_unverified_notes
- spend_fails_on_locked_notes
- ovk_policy_prevents_recovery_from_chain
- spend_succeeds_to_t_addr_zero_change
- change_note_spends_succeed
- external_address_change_spends_detected_in_restore_from_seed
- zip317_spend
- shield_transparent
- birthday_in_anchor_shard
- checkpoint_gaps
- pool_crossing_required
- fully_funded_fully_private
- fully_funded_send_to_t
- multi_pool_checkpoint
- multi_pool_checkpoints_with_pruning
- valid_chain_states
- invalid_chain_cache_disconnected
- data_db_truncation
- reorg_to_checkpoint
- scan_cached_blocks_allows_blocks_out_of_order
- scan_cached_blocks_finds_received_notes
- scan_cached_blocks_finds_change_notes
- scan_cached_blocks_detects_spends_out_of_order
- metadata_queries_exclude_unwanted_notes
- pczt_single_step
- wallet_recovery_computes_fees
- receive_two_notes_with_same_value
```

## High level steps present in (nearly) all test functions

 1 Setup Test State:                                                                               
    • This step is present in all functions. It involves initializing a test state with a data     
      store factory and block cache, and setting up an account from the Sapling activation block.  
 2 Add Funds:                                                                                      
    • Most functions include a step to add funds to the wallet, either as a single note or multiple
      notes.                                                                                       
 3 Verify Initial Balance:                                                                         
    • This step is common across functions to ensure that the total and spendable balances match   
      the added value.                                                                             
 4 Create Transaction Request:                                                                     
    • Many functions involve constructing a transaction request to send a specified amount to an   
      external address.                                                                            
 5 Setup Fee and Change Strategy:                                                                  
    • Defining the fee rule and change strategy for the transaction is a common step.              
 6 Propose Transfer:                                                                               
     • Proposing a transfer using the input selector and change strategy is a frequent action.     
  7 Create Proposed Transactions:                                                                  
     • Creating the proposed transactions and verifying that transaction IDs are returned is a     
       common step.                                                                                
  8 Verify Transaction Storage and Decryption:                                                     
     • Checking that the transaction was stored and that the outputs are decryptable is a recurring
       step.                                                                                       
  9 Verify Memos:                                                                                  
     • Ensuring that the correct memos are associated with the transaction outputs is often        
       included.                                                                                   
 10 Verify Sent Notes:                                                                             
     • Confirming that the sent notes match the expected details is a common verification step.    
 11 Verify Transaction History:                                                                    
     • Checking that the transaction history matches the expected values is a frequent action.     
 12 Decrypt and Store Transaction:                                                                 
     • Ensuring that the transaction can be decrypted and stored successfully is a common final    
       step.     

Function: send_single_step_proposed_transfer                                                       

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 10,000 Zatoshis to an external address.             
 5 Setup Fee and Change Strategy:                                                                  
    • Defines the fee rule and change strategy for the transaction.                                
  6 Propose Transfer:                                                                              
     • Proposes a transfer using the input selector and change strategy.                           
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
  9 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 10 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 11 Check Nonexistent Note:                                                                        
     • Verifies that querying for a nonexistent note returns None.                                 
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      

Function: zip_315_confirmations_test_steps                                                         

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Generate Confirmations:                                                                         
    • Mines blocks to generate confirmations and updates the test state.                           
 5 Verify Spendable Balance:                                                                       
    • Ensures that the spendable balance is zero until sufficient confirmations are reached.       
 6 Propose Transaction:                                                                            
    • Proposes a transaction once the funds are spendable.                                         
 7 Verify Proposal Success:                                                                        
    • Confirms that the proposal succeeds when the confirmation policy is met.                     

Function: spend_max_spendable_single_step_proposed_transfer                                        

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds two notes with a total value of 120,000 Zatoshis to the wallet.                         
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
     • Constructs a transaction request to send the maximum spendable amount to an external        
       address.                                                                                    
  5 Setup Fee and Change Strategy:                                                                 
     • Defines the fee rule and change strategy for the transaction.                               
  6 Propose Transfer:                                                                              
     • Proposes a transfer using the input selector and change strategy.                           
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
  9 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 10 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 11 Check Nonexistent Note:                                                                        
     • Verifies that querying for a nonexistent note returns None.                                 
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      

Function: spend_everything_single_step_proposed_transfer                                           

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send the entire balance to an external address.          
 5 Setup Fee and Change Strategy:                                                                  
    • Defines the fee rule and change strategy for the transaction.                                
  6 Propose Transfer:                                                                              
     • Proposes a transfer using the input selector and change strategy.                           
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
  9 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 10 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 11 Check Nonexistent Note:                                                                        
     • Verifies that querying for a nonexistent note returns None.                                 
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      

Function: fails_to_send_max_spendable_to_transparent_with_memo                                     

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send the maximum spendable amount to a transparent       
      address with a memo.                                                                         
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 6 Propose Transfer:                                                                               
    • Attempts to propose a transfer and expects it to fail due to the memo.                       
 7 Verify Failure:                                                                                 
    • Confirms that the proposal fails with the expected error.                                    

Function: spend_everything_proposal_fails_when_unconfirmed_funds_present                           

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Generate Empty Blocks:                                                                          
    • Mines empty blocks to simulate confirmations.                                                
 4 Add More Funds:                                                                                 
    • Adds additional funds to the wallet.                                                         
 5 Verify Balance:                                                                                 
    • Checks that the spendable balance does not match the total balance due to unconfirmed funds. 
  6 Create Transaction Request:                                                                    
     • Constructs a transaction request to send the entire balance to an external address.         
  7 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  8 Propose Transfer:                                                                              
     • Attempts to propose a transfer and expects it to fail due to unconfirmed funds.             
  9 Verify Failure:                                                                                
     • Confirms that the proposal fails with the expected error.                                   

Function: send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present                      

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Generate Empty Blocks:                                                                          
    • Mines empty blocks to simulate confirmations.                                                
 4 Add More Funds:                                                                                 
    • Adds additional funds to the wallet.                                                         
 5 Verify Balance:                                                                                 
    • Checks that the spendable balance does not match the total balance due to unconfirmed funds. 
  6 Create Transaction Request:                                                                    
     • Constructs a transaction request to send the maximum spendable amount to an external        
       address.                                                                                    
  7 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  8 Propose Transfer:                                                                              
     • Proposes a transfer and expects it to succeed despite unconfirmed funds.                    
  9 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
 10 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
 11 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 12 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 13 Check Nonexistent Note:                                                                        
     • Verifies that querying for a nonexistent note returns None.                                 
 14 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 15 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      

Function: spend_everything_multi_step_single_note_proposed_transfer                                

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 100,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Calculate Expected Fees and Balances:                                                           
    • Computes the expected fees and balances for the transaction.                                 
 5 Create Transaction Request:                                                                     
    • Constructs a transaction request to send the entire balance to a TEX address.                
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  9 Mine Transactions:                                                                             
     • Mines the created transactions and updates the test state.                                  
 10 Verify Sent Outputs:                                                                           
     • Checks that the sent outputs match the expected values.                                     
 11 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 12 Verify Ending Balance:                                                                         
     • Confirms that the ending balance is zero.                                                   

Function: spend_everything_multi_step_many_notes_proposed_transfer                                 

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds multiple notes with a total value of 300,000 Zatoshis to the wallet.                    
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Calculate Expected Fees and Balances:                                                           
    • Computes the expected fees and balances for the transaction.                                 
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to send the entire balance to a TEX address.               
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  9 Mine Transactions:                                                                             
     • Mines the created transactions and updates the test state.                                  
 10 Verify Sent Outputs:                                                                           
     • Checks that the sent outputs match the expected values.                                     
 11 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 12 Verify Ending Balance:                                                                         
     • Confirms that the ending balance is zero.                                                   

Function: spend_everything_multi_step_with_marginal_notes_proposed_transfer                        

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds multiple notes with a total value of 300,000 Zatoshis to the wallet.                    
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Calculate Expected Fees and Balances:                                                           
    • Computes the expected fees and balances for the transaction.                                 
 5 Create Transaction Request:                                                                     
    • Constructs a transaction request to send the entire balance to a TEX address.                
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  9 Mine Transactions:                                                                             
     • Mines the created transactions and updates the test state.                                  
 10 Verify Sent Outputs:                                                                           
     • Checks that the sent outputs match the expected values.                                     
 11 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 12 Verify Ending Balance:                                                                         
     • Confirms that the ending balance is zero.                                                   

Function: send_with_multiple_change_outputs                                                        

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 650,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 100,000 Zatoshis to an external address.            
  5 Setup Fee and Change Strategy:                                                                 
     • Defines the fee rule and change strategy for the transaction.                               
  6 Propose Transfer:                                                                              
     • Proposes a transfer using the input selector and change strategy.                           
  7 Verify Proposal Steps:                                                                         
     • Confirms that the proposal includes multiple change outputs.                                
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
 10 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 11 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      
 14 Create Another Proposal:                                                                       
     • Constructs another proposal with more outputs requested.                                    
 15 Verify Proposal Steps:                                                                         
     • Confirms that the new proposal includes the expected number of change outputs.              

Function: send_multi_step_proposed_transfer                                                        

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 100,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Calculate Expected Fees and Balances:                                                           
    • Computes the expected fees and balances for the transaction.                                 
 5 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 50,000 Zatoshis to a TEX address.                   
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  9 Mine Transactions:                                                                             
     • Mines the created transactions and updates the test state.                                  
 10 Verify Sent Outputs:                                                                           
     • Checks that the sent outputs match the expected values.                                     
 11 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 12 Verify Ending Balance:                                                                         
     • Confirms that the ending balance is zero.                                                   
 13 Simulate External Send:                                                                        
     • Simulates sending to an ephemeral address within the current gap limit.                     
 14 Verify Address Reservation:                                                                    
     • Confirms that address reservation behaves as expected.                                      

Function: spend_all_funds_single_step_proposed_transfer                                            

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 60,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 50,000 Zatoshis to an external address.             
 5 Setup Fee and Change Strategy:                                                                  
     • Defines the fee rule and change strategy for the transaction.                               
  6 Propose Transfer:                                                                              
     • Proposes a transfer using the input selector and change strategy.                           
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
  9 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 10 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 11 Check Nonexistent Note:                                                                        
     • Verifies that querying for a nonexistent note returns None.                                 
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      

Function: spend_all_funds_multi_step_proposed_transfer                                             

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 100,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Calculate Expected Fees and Balances:                                                           
    • Computes the expected fees and balances for the transaction.                                 
 5 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 75,000 Zatoshis to a TEX address.                   
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  9 Mine Transactions:                                                                             
     • Mines the created transactions and updates the test state.                                  
 10 Verify Sent Outputs:                                                                           
     • Checks that the sent outputs match the expected values.                                     
 11 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 12 Verify Ending Balance:                                                                         
     • Confirms that the ending balance is zero.                                                   

Function: proposal_fails_if_not_all_ephemeral_outputs_consumed                                     

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 100,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 50,000 Zatoshis to a TEX address.                   
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 6 Propose Transfer:                                                                               
    • Proposes a transfer and verifies the proposal steps.                                         
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that two transaction IDs are returned.       
  8 Frobnicate Proposal:                                                                           
     • Modifies the proposal to make it invalid by not consuming all ephemeral outputs.            
  9 Verify Failure:                                                                                
     • Confirms that the proposal fails with the expected error.                                   

Function: create_to_address_fails_on_incorrect_usk                                                 

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Incorrect USK:                                                                           
    • Creates a Unified Spending Key (USK) that doesn't exist in the wallet.                       
 3 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 1 Zatoshi to an external address.                   
 4 Setup Fee and Change Strategy:                                                                  
    • Defines the fee rule and change strategy for the transaction.                                
 5 Attempt Spend:                                                                                  
    • Attempts to spend with the incorrect USK and expects it to fail.                             
 6 Verify Failure:                                                                                 
    • Confirms that the spend fails with the expected error.                                       

Function: proposal_fails_with_no_blocks                                                            

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Verify Wallet Summary:                                                                          
    • Confirms that the wallet summary is not available.                                           
 3 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 1 Zatoshi to an external address.                   
 4 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 5 Attempt Proposal:                                                                               
    • Attempts to propose a transfer and expects it to fail due to lack of synchronization.        
 6 Verify Failure:                                                                                 
    • Confirms that the proposal fails with the expected error.                                    

Function: spend_fails_on_unverified_notes                                                          

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 50,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Add More Funds:                                                                                 
    • Adds additional funds to the wallet.                                                         
  5 Verify Balance:                                                                                
     • Checks that the spendable balance does not match the total balance due to unverified notes. 
  6 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 70,000 Zatoshis to an external address.            
  7 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  8 Attempt Proposal:                                                                              
     • Attempts to propose a transfer and expects it to fail due to insufficient verified notes.   
  9 Verify Failure:                                                                                
     • Confirms that the proposal fails with the expected error.                                   
 10 Mine Blocks:                                                                                   
     • Mines blocks to verify the second note.                                                     
 11 Verify Balance:                                                                                
     • Checks that the spendable balance now includes the second note.                             
 12 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 70,000 Zatoshis to an external address.            
 13 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
 14 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
 15 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
 16 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 17 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: spend_fails_on_locked_notes                                                              

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 50,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 15,000 Zatoshis to an external address.             
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
  6 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Attempt Second Proposal:                                                                       
     • Attempts a second proposal and expects it to fail due to locked notes.                      
  9 Verify Failure:                                                                                
     • Confirms that the second proposal fails with the expected error.                            
 10 Mine Blocks:                                                                                   
     • Mines blocks to expire the first transaction.                                               
 11 Verify Balance:                                                                                
     • Checks that the spendable balance matches the total balance.                                
 12 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 2,000 Zatoshis to an external address.             
 13 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
 14 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
 15 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
 16 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 17 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: ovk_policy_prevents_recovery_from_chain                                                  

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 50,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 15,000 Zatoshis to an external address.             
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
  6 Send and Recover with Policy:                                                                  
     • Sends funds and attempts to recover with different OVK policies.                            
  7 Verify Recovery:                                                                               
     • Confirms that recovery behaves as expected based on the OVK policy.                         
  8 Mine Blocks:                                                                                   
     • Mines blocks to expire the first transaction.                                               
  9 Send and Recover with Policy:                                                                  
     • Sends funds and attempts to recover with different OVK policies.                            
 10 Verify Recovery:                                                                               
     • Confirms that recovery behaves as expected based on the OVK policy.                         

Function: spend_succeeds_to_t_addr_zero_change                                                     

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 70,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 50,000 Zatoshis to a transparent address.           
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 6 Propose Transfer:                                                                               
    • Proposes a transfer and verifies the proposal steps.                                         
 7 Create Proposed Transactions:                                                                   
    • Creates the proposed transactions and verifies that one transaction ID is returned.          
 8 Verify Success:                                                                                 
    • Confirms that the transfer succeeds.                                                         

Function: change_note_spends_succeed                                                               

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 70,000 Zatoshis to the wallet.                            
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Verify Change Note Scope:                                                                       
    • Confirms that the change note is owned by the internal spending key.                         
 5 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 50,000 Zatoshis to a transparent address.           
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Verify Success:                                                                                
     • Confirms that the transfer succeeds.                                                        

Function: external_address_change_spends_detected_in_restore_from_seed                             

 1 Setup Test State:                                                                               
     • Initializes a test state with a data store factory and block cache.                         
     • Sets up an account from the Sapling activation block.                                       
  2 Create Accounts:                                                                               
     • Creates two accounts with the same seed and birthday.                                       
  3 Add Funds:                                                                                     
     • Adds a single note with a value of 100,000 Zatoshis to the first account.                   
  4 Verify Initial Balance:                                                                        
     • Checks that the total and spendable balances match the added value.                         
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to send funds to an external address and back to the       
       originating wallet.                                                                         
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 10 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         
 11 Reset Wallet:                                                                                  
     • Resets the wallet and restores accounts from the seed.                                      
 12 Scan Blocks:                                                                                   
     • Scans the blocks and verifies the restored balance.                                         

Function: zip317_spend                                                                             

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 50,000 Zatoshis to the wallet.                            
 3 Add Dust Notes:                                                                                 
    • Adds multiple dust notes to the wallet.                                                      
 4 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 50,000 Zatoshis to an external address.            
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Attempt Spend:                                                                                 
     • Attempts to spend and expects it to fail due to insufficient non-dust funds.                
  8 Verify Failure:                                                                                
     • Confirms that the spend fails with the expected error.                                      
  9 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 41,000 Zatoshis to an external address.            
 10 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
 11 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
 12 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
 13 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 14 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: shield_transparent                                                                       

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 50,000 Zatoshis to the wallet.                            
  3 Add UTXO:                                                                                      
     • Adds a UTXO to the wallet.                                                                  
  4 Verify Initial Balance:                                                                        
     • Checks that the total and spendable balances match the added value.                         
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to shield transparent funds.                               
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Shielding:                                                                             
     • Proposes a shielding transaction and verifies the proposal steps.                           
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Verify Transaction Storage and Decryption:                                                     
     • Checks that the transaction was stored and that the outputs are decryptable.                
 10 Verify Memos:                                                                                  
     • Ensures that the correct memos are associated with the transaction outputs.                 
 11 Verify Sent Notes:                                                                             
     • Confirms that the sent notes match the expected details.                                    
 12 Verify Transaction History:                                                                    
     • Checks that the transaction history matches the expected values.                            
 13 Decrypt and Store Transaction:                                                                 
     • Ensures that the transaction can be decrypted and stored successfully.                      
 14 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 15 Verify Enhancement Request:                                                                    
     • Confirms that a transaction enhancement request was created.                                
 16 Advance Chain:                                                                                 
     • Advances the chain to expire the enhancement request.                                       
 17 Verify Enhancement Request:                                                                    
     • Confirms that the enhancement request was deleted.                                          

Function: birthday_in_anchor_shard                                                                 

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Generate Blocks:                                                                                
    • Generates blocks with and without value for the wallet.                                      
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies that the received note is not spendable.                           
 4 Scan Skipped Blocks:                                                                            
    • Scans skipped blocks and verifies that the received note is now spendable.                   
 5 Verify Spendable Notes:                                                                         
    • Confirms that the spendable notes match the expected values.                                 

Function: checkpoint_gaps                                                                          

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Generate Blocks:                                                                                
    • Generates blocks with and without value for the wallet.                                      
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies that the received note is spendable.                               
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 10,000 Zatoshis to an external address.             
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 6 Propose Transfer:                                                                               
    • Proposes a transfer and verifies the proposal steps.                                         
 7 Create Proposed Transactions:                                                                   
    • Creates the proposed transactions and verifies that one transaction ID is returned.          
 8 Verify Success:                                                                                 
    • Confirms that the transfer succeeds.                                                         

Function: pool_crossing_required                                                                   

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 350,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
     • Constructs a transaction request to send 200,000 Zatoshis to an external address.           
  5 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  6 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
  9 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: fully_funded_fully_private                                                               

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds multiple notes with a total value of 700,000 Zatoshis to the wallet.                    
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
  4 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 200,000 Zatoshis to an external address.           
  5 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  6 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
  9 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: fully_funded_send_to_t                                                                   

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds multiple notes with a total value of 700,000 Zatoshis to the wallet.                    
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 200,000 Zatoshis to a transparent address.          
  5 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  6 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  7 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  8 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
  9 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         

Function: multi_pool_checkpoint                                                                    

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds multiple notes with a total value of 1,500,000 Zatoshis to the wallet.                  
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
  4 Generate Empty Blocks:                                                                         
     • Mines empty blocks to simulate confirmations.                                               
  5 Scan Blocks:                                                                                   
     • Scans blocks and verifies the balance.                                                      
  6 Create Transaction Request:                                                                    
     • Constructs a transaction request to send 200,000 Zatoshis to an external address.           
  7 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  8 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  9 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
 10 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 11 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         
 12 Verify Checkpoints:                                                                            
     • Confirms that the checkpoints match the expected values.                                    

Function: multi_pool_checkpoints_with_pruning                                                      

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Generate Blocks:                                                                                
    • Generates blocks with and without value for the wallet.                                      
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Verify Checkpoints:                                                                             
    • Confirms that the checkpoints match the expected values.                                     

Function: valid_chain_states                                                                       

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Verify Initial Chain State:                                                                     
    • Confirms that the initial chain state is None.                                               
 3 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 4 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 5 Verify Chain State:                                                                             
    • Confirms that the chain state is valid.                                                      

Function: invalid_chain_cache_disconnected                                                         

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Create Disconnected Blocks:                                                                     
    • Creates blocks that don't connect to the scanned ones.                                       
 5 Verify Chain State:                                                                             
    • Confirms that the chain state is invalid at the data/cache boundary.                         

Function: data_db_truncation                                                                       

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Truncate Database:                                                                              
    • Truncates the database to a specific height.                                                 
 5 Verify Balance:                                                                                 
    • Confirms that the balance reflects the truncated state.                                      
 6 Scan Blocks:                                                                                    
    • Scans blocks again and verifies the balance.                                                 

Function: reorg_to_checkpoint                                                                      

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Truncate Database:                                                                              
    • Truncates the database to a specific height.                                                 
 5 Create New Blocks:                                                                              
    • Creates new blocks with different values.                                                    
 6 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 7 Verify Checkpoints:                                                                             
    • Confirms that the checkpoints match the expected values.                                     

Function: scan_cached_blocks_allows_blocks_out_of_order                                            

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks out of order and verifies the balance.                                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 110,000 Zatoshis to an external address.            
 5 Setup Fee Rule:                                                                                 
    • Defines the fee rule for the transaction.                                                    
 6 Propose Transfer:                                                                               
    • Proposes a transfer and verifies the proposal steps.                                         
 7 Create Proposed Transactions:                                                                   
    • Creates the proposed transactions and verifies that one transaction ID is returned.          
 8 Verify Success:                                                                                 
    • Confirms that the transfer succeeds.                                                         

Function: scan_cached_blocks_finds_received_notes                                                  

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Create Blocks:                                                                                  
    • Creates additional blocks with value for the wallet.                                         
 5 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 6 Verify Balance:                                                                                 
    • Confirms that the balance reflects the received notes.                                       

Function: scan_cached_blocks_finds_change_notes                                                    

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 4 Create Blocks:                                                                                  
    • Creates additional blocks with value for the wallet.                                         
 5 Scan Blocks:                                                                                    
    • Scans blocks and verifies the balance.                                                       
 6 Verify Balance:                                                                                 
    • Confirms that the balance reflects the change notes.                                         

Function: scan_cached_blocks_detects_spends_out_of_order                                           

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Blocks:                                                                                  
    • Creates blocks with value for the wallet.                                                    
 3 Create Blocks:                                                                                  
    • Creates additional blocks with value for the wallet.                                         
 4 Scan Blocks:                                                                                    
    • Scans blocks out of order and verifies the balance.                                          
 5 Verify Balance:                                                                                 
    • Confirms that the balance reflects the spent notes.                                          

Function: metadata_queries_exclude_unwanted_notes                                                  

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
  2 Create Blocks:                                                                                 
     • Creates blocks with value for the wallet.                                                   
  3 Scan Blocks:                                                                                   
     • Scans blocks and verifies the balance.                                                      
  4 Test Metadata Queries:                                                                         
     • Tests metadata queries with different filters and verifies the results.                     
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to send half of each note's value.                         
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 10 Verify Metadata Queries:                                                                       
     • Tests metadata queries with different filters and verifies the results.                     

Function: pczt_single_step                                                                         

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds a single note with a value of 350,000 Zatoshis to the wallet.                           
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Create Transaction Request:                                                                     
    • Constructs a transaction request to send 200,000 Zatoshis to an external address.            
  5 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  6 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  7 Create PCZT:                                                                                   
     • Creates a PCZT from the proposal and verifies the result.                                   
  8 Verify Extraction Failure:                                                                     
     • Confirms that extraction fails without proofs or signatures.                                
  9 Add Proof Generation Keys:                                                                     
     • Adds proof generation keys to the PCZT.                                                     
 10 Create Proofs:                                                                                 
     • Creates proofs for the PCZT.                                                                
 11 Apply Signatures:                                                                              
     • Applies signatures to the PCZT.                                                             
 12 Extract and Store Transaction:                                                                 
     • Extracts and stores the transaction from the PCZT.                                          
 13 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   

Function: wallet_recovery_computes_fees                                                            

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Create Accounts:                                                                                
    • Creates two accounts with the same seed and birthday.                                        
  3 Add Funds:                                                                                     
     • Adds multiple notes with a total value of 700,000 Zatoshis to the first account.            
  4 Verify Initial Balance:                                                                        
     • Checks that the total and spendable balances match the added value.                         
  5 Create Transaction Request:                                                                    
     • Constructs a transaction request to send funds to a transparent address in the second       
       account.                                                                                    
  6 Setup Fee Rule:                                                                                
     • Defines the fee rule for the transaction.                                                   
  7 Propose Transfer:                                                                              
     • Proposes a transfer and verifies the proposal steps.                                        
  8 Create Proposed Transactions:                                                                  
     • Creates the proposed transactions and verifies that one transaction ID is returned.         
  9 Mine Transaction:                                                                              
     • Mines the created transaction and updates the test state.                                   
 10 Verify Balance:                                                                                
     • Confirms that the balance reflects the sent amount.                                         
 11 Shield Funds:                                                                                  
     • Shields the funds in the second account.                                                    
 12 Verify Fee Information:                                                                        
     • Confirms that the fee information is present.                                               
 13 Intervene:                                                                                     
     • Deletes fee information for the transaction.                                                
 14 Verify Fee Deletion:                                                                           
     • Confirms that the fee information was deleted.                                              
 15 Decrypt and Store Transaction:                                                                 
     • Decrypts and stores the transaction to restore fee information.                             
 16 Verify Fee Restoration:                                                                        
     • Confirms that the fee information was restored.                                             
 17 Intervene Again:                                                                               
     • Deletes fee information for the transaction.                                                
 18 Verify Fee Deletion:                                                                           
     • Confirms that the fee information was deleted.                                              
 19 Decrypt and Store Input Transaction:                                                           
     • Decrypts and stores the input transaction to restore fee information.                       
 20 Verify Fee Restoration:                                                                        
     • Confirms that the fee information was restored.                                             

Function: receive_two_notes_with_same_value                                                        

 1 Setup Test State:                                                                               
    • Initializes a test state with a data store factory and block cache.                          
    • Sets up an account from the Sapling activation block.                                        
 2 Add Funds:                                                                                      
    • Adds two identical notes with a total value of 120,000 Zatoshis to the wallet.               
 3 Verify Initial Balance:                                                                         
    • Checks that the total and spendable balances match the added value.                          
 4 Verify Unspent Notes:                                                                           
    • Confirms that both notes are unspent.                                                        
 5 Verify Spendable Notes:                                                                         
    • Confirms that both notes are spendable.  
