(function() {
    var type_impls = Object.fromEntries([["zcash_primitives",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-TxOut\" class=\"impl\"><a href=\"#impl-Clone-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","zcash_primitives::transaction::components::TxOut"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-TxOut\" class=\"impl\"><a href=\"#impl-Debug-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","zcash_primitives::transaction::components::TxOut"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-OutputView-for-TxOut\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_primitives/transaction/fees/transparent.rs.html#87-95\">Source</a><a href=\"#impl-OutputView-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"zcash_primitives/transaction/fees/transparent/trait.OutputView.html\" title=\"trait zcash_primitives::transaction::fees::transparent::OutputView\">OutputView</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.value\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_primitives/transaction/fees/transparent.rs.html#88-90\">Source</a><a href=\"#method.value\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"zcash_primitives/transaction/fees/transparent/trait.OutputView.html#tymethod.value\" class=\"fn\">value</a>(&amp;self) -&gt; Zatoshis</h4></section></summary><div class='docblock'>Returns the value of the output being created.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.script_pubkey\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_primitives/transaction/fees/transparent.rs.html#92-94\">Source</a><a href=\"#method.script_pubkey\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"zcash_primitives/transaction/fees/transparent/trait.OutputView.html#tymethod.script_pubkey\" class=\"fn\">script_pubkey</a>(&amp;self) -&gt; &amp;<a class=\"struct\" href=\"zcash_primitives/legacy/struct.Script.html\" title=\"struct zcash_primitives::legacy::Script\">Script</a></h4></section></summary><div class='docblock'>Returns the script corresponding to the newly created output.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialized_size\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_primitives/transaction/fees/transparent.rs.html#80-84\">Source</a><a href=\"#method.serialized_size\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"zcash_primitives/transaction/fees/transparent/trait.OutputView.html#method.serialized_size\" class=\"fn\">serialized_size</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Returns the serialized size of the txout.</div></details></div></details>","OutputView","zcash_primitives::transaction::components::TxOut"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-TxOut\" class=\"impl\"><a href=\"#impl-PartialEq-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#261\">Source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","zcash_primitives::transaction::components::TxOut"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TxOut\" class=\"impl\"><a href=\"#impl-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section></summary><div class=\"impl-items\"><section id=\"method.read\" class=\"method\"><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html#tymethod.read\" class=\"fn\">read</a>&lt;R&gt;(reader: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt;<div class=\"where\">where\n    R: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/std/io/trait.Read.html\" title=\"trait std::io::Read\">Read</a>,</div></h4></section><section id=\"method.write\" class=\"method\"><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html#tymethod.write\" class=\"fn\">write</a>&lt;W&gt;(&amp;self, writer: W) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt;<div class=\"where\">where\n    W: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/std/io/trait.Write.html\" title=\"trait std::io::Write\">Write</a>,</div></h4></section><details class=\"toggle method-toggle\" open><summary><section id=\"method.recipient_address\" class=\"method\"><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html#tymethod.recipient_address\" class=\"fn\">recipient_address</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"zcash_primitives/legacy/enum.TransparentAddress.html\" title=\"enum zcash_primitives::legacy::TransparentAddress\">TransparentAddress</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Returns the address to which the TxOut was sent, if this is a valid P2SH or P2PKH output.</p>\n</div></details></div></details>",0,"zcash_primitives::transaction::components::TxOut"],["<section id=\"impl-Eq-for-TxOut\" class=\"impl\"><a href=\"#impl-Eq-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section>","Eq","zcash_primitives::transaction::components::TxOut"],["<section id=\"impl-StructuralPartialEq-for-TxOut\" class=\"impl\"><a href=\"#impl-StructuralPartialEq-for-TxOut\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxOut.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxOut\">TxOut</a></h3></section>","StructuralPartialEq","zcash_primitives::transaction::components::TxOut"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[13246]}