# Testing DSL

## Analysis of prior art

The following is a step-by-step analysis of each test function. I'm using this
analysis to inform what abstractions to employ in the testing DSL.

### High level steps present in (nearly) all test functions

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

### Existing test functions

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
