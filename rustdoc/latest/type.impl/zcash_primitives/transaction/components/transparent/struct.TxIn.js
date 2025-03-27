(function() {
    var type_impls = Object.fromEntries([["zcash_primitives",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-TxIn%3CA%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#impl-Clone-for-TxIn%3CA%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;<div class=\"where\">where\n    A: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>,\n    &lt;A as <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>&gt;::<a class=\"associatedtype\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html#associatedtype.ScriptSig\" title=\"type zcash_primitives::transaction::components::transparent::Authorization::ScriptSig\">ScriptSig</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#174\">Source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: &amp;Self)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","zcash_primitives::transaction::components::TxIn"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-TxIn%3CA%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#impl-Debug-for-TxIn%3CA%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;<div class=\"where\">where\n    A: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>,\n    &lt;A as <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>&gt;::<a class=\"associatedtype\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html#associatedtype.ScriptSig\" title=\"type zcash_primitives::transaction::components::transparent::Authorization::ScriptSig\">ScriptSig</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","zcash_primitives::transaction::components::TxIn"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-TxIn%3CA%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#impl-PartialEq-for-TxIn%3CA%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;<div class=\"where\">where\n    A: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> + <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>,\n    &lt;A as <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>&gt;::<a class=\"associatedtype\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html#associatedtype.ScriptSig\" title=\"type zcash_primitives::transaction::components::transparent::Authorization::ScriptSig\">ScriptSig</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>self</code> and <code>other</code> values to be equal, and is used by <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#262\">Source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>Tests for <code>!=</code>. The default implementation is almost always sufficient,\nand should not be overridden without very good reason.</div></details></div></details>","PartialEq","zcash_primitives::transaction::components::TxIn"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TxIn%3CAuthorized%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#202\">Source</a><a href=\"#impl-TxIn%3CAuthorized%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.Authorized.html\" title=\"struct zcash_primitives::transaction::components::transparent::Authorized\">Authorized</a>&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.read\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#203\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html#tymethod.read\" class=\"fn\">read</a>&lt;R&gt;(reader: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut R</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.Authorized.html\" title=\"struct zcash_primitives::transaction::components::transparent::Authorized\">Authorized</a>&gt;, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt;<div class=\"where\">where\n    R: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/std/io/trait.Read.html\" title=\"trait std::io::Read\">Read</a>,</div></h4></section><section id=\"method.write\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#219\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html#tymethod.write\" class=\"fn\">write</a>&lt;W&gt;(&amp;self, writer: W) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/std/io/error/struct.Error.html\" title=\"struct std::io::error::Error\">Error</a>&gt;<div class=\"where\">where\n    W: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/std/io/trait.Write.html\" title=\"trait std::io::Write\">Write</a>,</div></h4></section></div></details>",0,"zcash_primitives::transaction::components::TxIn"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TxIn%3CUnauthorized%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/builder.rs.html#281\">Source</a><a href=\"#impl-TxIn%3CUnauthorized%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/builder/struct.Unauthorized.html\" title=\"struct zcash_primitives::transaction::components::transparent::builder::Unauthorized\">Unauthorized</a>&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/zcash_transparent/builder.rs.html#283\">Source</a><h4 class=\"code-header\">pub fn <a href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html#tymethod.new\" class=\"fn\">new</a>(prevout: <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.OutPoint.html\" title=\"struct zcash_primitives::transaction::components::transparent::OutPoint\">OutPoint</a>) -&gt; <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;<a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/builder/struct.Unauthorized.html\" title=\"struct zcash_primitives::transaction::components::transparent::builder::Unauthorized\">Unauthorized</a>&gt;</h4></section><span class=\"item-info\"><div class=\"stab portability\">Available on <strong>crate feature <code>transparent-inputs</code></strong> only.</div></span></div></details>",0,"zcash_primitives::transaction::components::TxIn"],["<section id=\"impl-StructuralPartialEq-for-TxIn%3CA%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/zcash_transparent/bundle.rs.html#195\">Source</a><a href=\"#impl-StructuralPartialEq-for-TxIn%3CA%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"zcash_primitives/transaction/components/transparent/struct.TxIn.html\" title=\"struct zcash_primitives::transaction::components::transparent::TxIn\">TxIn</a>&lt;A&gt;<div class=\"where\">where\n    A: <a class=\"trait\" href=\"zcash_primitives/transaction/components/transparent/trait.Authorization.html\" title=\"trait zcash_primitives::transaction::components::transparent::Authorization\">Authorization</a>,</div></h3></section>","StructuralPartialEq","zcash_primitives::transaction::components::TxIn"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[15767]}