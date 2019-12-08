This specification describes the logic for Bolt anonymous payment channels using Whitelisted Transparent Programs (WTPs).

1. Customer and Merchant Signing Keys
-------------

The customer and the merchant both have key pairs from a suitable signature scheme. These are denoted as:
``<cust-pk>, <cust-sk>`` and 
``<merch-pk>, <merch-sk>``, respectively, where ``pk`` stands for "public key" and ``sk`` stands for the corresponding "secret key".

The merchant must be able to issue blind signatures, so they have an additional keypair; this keypair is denoted as:
``<MERCH-PK>, <MERCH-SK>``.

The customer key pair is specific to the channel and must not be reused. The merchant key pair is long term and should be used for all customer channels. 

2. Wallets
-------------
A Bolt channel allows a customer to make or receive a sequence of payments off chain. These payments are tracked and validated using a sequence of *wallets*. A wallet consists of the customer's public key (which ties the wallet to the channel), a wallet-specific public key (which can be from any suitable signature scheme), denoted ``<wpk>``, and the current customer and merchant balances.

After each payment, the customer receives an updated wallet and blind signatures from the merchant on the wallet contents allowing channel close as specified below.

2.1 Opening a Channel: Overview
-------------
To open a channel, the customer and merchant exchange key information and set the channel token ``<channel-token> = <cust-pk>, <merch-pk>, <MERCH-PK>``. 

They agree on their respective initial balances ``initial-cust-balance`` and ``initial-merch-balance``.

The customer picks an inital wallet public key ``<wpk>``.

The customer and merchant escrow the necessary funds in a funding transaction, denoted ``escrow-tx``. 

2.2 Closing a Channel: Overview
-------------

A customer should be able to close the channel by posting a *closing token* ``close-token``, which is a blind signature from the merchant under ``<MERCH-PK>`` on a special closing wallet that contains ``<cust-pk>, <wpk>, <balance-cust>, <balance-merch>, CLOSE``. We use ``cust-close-tx`` to denote the transaction posted by the customer to initiate channel closure.

A merchant should be able to close the channel by either posting a special closing transaction ``merch-close-tx`` (detailed in Section 2.3.2) or, if the customer posts an outdated version of their closing token, a signed revocation token, ``revocation-token`` as detailed below. The revocation token ``revocation-token`` is a signature under the wallet public key ``<wpk>`` on the special revocation message ``<wpk> || REVOKED``. The transaction posted by the merchant to dispute is denoted ``dispute-tx``.

The customer and merchant may also negotiate off-chain to form a *mutual close transaction*, ``mutual-close-tx``. Off-chain collaboration to create ``mutual-close-tx`` reduces the required number of on-chain transactions and eliminates the time delays.

3. Transparent/Shielded Tx: Using T/Z-addresses and WTPs
-------------

We assume the following specific features are present:

(1) Support for whitelisted transparent programs (WTPs) that enables 2-of-2 multi-sig style transactions
(2) Can specify absolute lock time in transaction
(3) Can specify relative lock time in transparent program
(4) Can specify shielded inputs and outputs
(5) A non-SegWit approach that fixes transaction malleability
(6) ``OP_BOLT`` logic expressed as WTPs. We will use the Bolt WTPs defined in Section 2.1: ``open-channel``, ``cust-close``, and ``merch-close``.

**Privacy Limitations**. The aggregate balance of the channel will be revealed in the funding transaction ``escrow-tx``. Similarly, the final splitting of funds will be revealed to the network. However, for channel opening and closing, the identity of the participants remains hidden. Channel opening and closing will also be distinguishable on the network due to use of WTPs.

**Channel Opening**. The funding transaction ``escrow-tx`` spends ZEC from one or more shielded addresses to a transparent output that is encumbered by a Bolt transparent program. See Section 2.1 for what the funding transaction looks like when instantiated using WTPs.

2.1 Bolt WTPs
--------------

Transparent programs take as input a ``predicate``, ``witness``, and ``context`` and then output a ``True`` or ``False`` on the stack. Bolt-specific transparent programs are deterministic and any malleation of the ``witness`` will result in a ``False`` output. The WTPs are as follows:

1. ``open-channel`` program. The purpose of this WTP is to encumber the funding transaction such that either party may initiate channel closing as detailed above in Section 1.3. The program is structured as follows:

	a. ``predicate``: The predicate consists of ``<<channel-token> || <merch-close-address>>``, where ``<channel-token> = <<cust-pk> || <merch-pk> || <MERCH-PK>>`` contains three public keys, one for the customer and two for the merchant, and an address ``<merch-close-address>`` for the merchant at which to receive funds from a customer-initiated close.
	
	b. ``witness``: The witness is defined as follows, where the first byte is used to denote witness type:
	
    		1. ``<<0x0> || <balance-cust> || <balance-merch> || <cust-sig> || <merch-sig>>``
    		2. ``<<0x1> || <balance-cust> || <balance-merch> || <cust-sig> || <wpk> || <closing-token>>``
  	
	c. ``verify_program`` behaves as follows:
	
    		1. If witness is of type ``0x0``, check that 2 new outputs are created, with the specified balances (unless one of the balances is zero), and that the signatures verify.
    		2. If witness is of type ``0x1``, check that 2 new outputs are created (unless one of the balances is zero), with the specified balances:
		
      			+ one paying ``<balance-merch>`` to ``<merch-close-address>`` 
      			+ one paying a ``cust-close`` WTP containing ``<channel-token>`` and ``<wallet> = <<wpk> || <balance-cust> || <balance-merch>>``
			
      			Also check that ``<cust-sig>`` is a valid signature and that ``<closing-token>`` contains a valid signature under ``<MERCH-PK>`` on ``<<cust-pk> || <wpk> || <balance-cust> || <balance-merch> || CLOSE>``.

2. ``cust-close`` program. The purpose of this WTP is to allow the customer to initiate channel closure as specified in Section 1.3. The program is specified as follows:

	a. ``predicate``: ``<<channel-token> || <block-height> || <wallet>>``, where
	
		1. ``<channel-token> = <<cust-pk> || <merch-pk> || <MERCH-PK>>``,
		2. ``<block_height>`` is the earliest block-height when balance can be spend, and
		3. ``<wallet> = <<wpk> || <balance-cust> || <balance-merch>>``.
	b. ``witness``: The witness is defined as one of the following, where the first byte is used to denote witness type:
	
		1. ``<<0x0> || <cust-sig>>``
		2. ``<<0x1> || <merch-sig> || <address> || <revocation-token>>``
	c. ``verify_program`` behaves as follows:
	
		1. If witness is of type ``0x0``, check that ``<cust-sig>`` is valid and ``<block-height>`` has been reached
		2. If witness is of type ``0x1``, check that 1 output is created paying ``<balance-cust>`` to ``<address>``. Also check that ``<merch-sig>`` is a valid signature on ``<<address> || <revocation-token>>`` and that ``<revocation-token>`` contains a valid signature under ``<wpk>`` on ``<<wpk> || REVOKED>``.

3. ``merch-close``. The purpose of this WTP is to allow a merchant to initiate channel closure as specified in Section 1.3. The program is specified as follows:

	a. ``predicate``: ``<<channel-token> || <block-height> || <merch-close-address>>``.
	b. ``witness`` is defined as one of the following, where the first byte is used to denote witness type:
	
		1. ``<<0x0> || <merch-sig>>``
		2. ``<<0x1> || <cust-sig> || <wallet> || <closing-token>>``, where ``<wallet> = <<wpk> || <balance-cust> || <balance-merch>>``.
	c. ``verify_program`` behaves as follows:
		
			1. If witness is of type ``0x0``, check that ``<merch-sig>`` is valid and ``<block-height>`` has been reached
			2. If witness is of type ``0x1``, check that 2 new outputs are created (unless one of the balances is zero), with the specified balances:
			
				+ one paying ``<balance-merch>`` to ``<merch-close-address>`` 
 				+ one paying a ``cust_close`` WTP containing ``<wallet> = <<wpk> || <balance-cust> || <balance-merch>>``  and ``<channel-token>``. 
				
				Also check that ``<cust-sig>`` is a valid signature and that ``<closing-token>`` contains a valid signature under ``<MERCH-PK>`` on ``<<cust-pk> || <wpk> || <balance-cust> || <balance-merch> || CLOSE>``.