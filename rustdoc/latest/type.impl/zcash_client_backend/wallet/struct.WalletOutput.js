(function() {
    var type_impls = Object.fromEntries([["zcash_client_backend",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-WalletOutput%3CNote,+Nullifier,+AccountId%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#353-412\">Source</a><a href=\"#impl-WalletOutput%3CNote,+Nullifier,+AccountId%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;Note, Nullifier, AccountId&gt; <a class=\"struct\" href=\"zcash_client_backend/wallet/struct.WalletOutput.html\" title=\"struct zcash_client_backend::wallet::WalletOutput\">WalletOutput</a>&lt;Note, Nullifier, AccountId&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_parts\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#356-376\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.from_parts\" class=\"fn\">from_parts</a>(\n    index: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>,\n    ephemeral_key: EphemeralKeyBytes,\n    note: Note,\n    is_change: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a>,\n    note_commitment_tree_position: Position,\n    nf: <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;Nullifier&gt;,\n    account_id: AccountId,\n    recipient_key_scope: <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;Scope&gt;,\n) -&gt; Self</h4></section></summary><div class=\"docblock\"><p>Constructs a new <code>WalletOutput</code> value from its constituent parts.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.index\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#379-381\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.index\" class=\"fn\">index</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class=\"docblock\"><p>The index of the output or action in the transaction that created this output.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ephemeral_key\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#383-385\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.ephemeral_key\" class=\"fn\">ephemeral_key</a>(&amp;self) -&gt; &amp;EphemeralKeyBytes</h4></section></summary><div class=\"docblock\"><p>The [<code>EphemeralKeyBytes</code>] used in the decryption of the note.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.note\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#387-389\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.note\" class=\"fn\">note</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Note</a></h4></section></summary><div class=\"docblock\"><p>The note.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.is_change\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#392-394\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.is_change\" class=\"fn\">is_change</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class=\"docblock\"><p>A flag indicating whether the process of note decryption determined that this\noutput should be classified as change.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.note_commitment_tree_position\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#396-398\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.note_commitment_tree_position\" class=\"fn\">note_commitment_tree_position</a>(&amp;self) -&gt; Position</h4></section></summary><div class=\"docblock\"><p>The position of the note in the global note commitment tree.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.nf\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#400-402\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.nf\" class=\"fn\">nf</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Nullifier</a>&gt;</h4></section></summary><div class=\"docblock\"><p>The nullifier for the note, if the key used to decrypt the note was able to compute it.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.account_id\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#404-406\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.account_id\" class=\"fn\">account_id</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;AccountId</a></h4></section></summary><div class=\"docblock\"><p>The identifier for the account to which the output belongs.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.recipient_key_scope\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_client_backend/wallet.rs.html#409-411\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_client_backend/wallet/struct.WalletOutput.html#tymethod.recipient_key_scope\" class=\"fn\">recipient_key_scope</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;Scope&gt;</h4></section></summary><div class=\"docblock\"><p>The ZIP 32 scope for which the viewing key that decrypted this output was derived, if\nknown.</p>\n</div></details></div></details>",0,"zcash_client_backend::wallet::WalletSaplingOutput"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[6891]}