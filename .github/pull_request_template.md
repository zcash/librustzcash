<!-- Thank you for your contribution! -->

<!-- This template is intended to help you be most successful in contributing. While it may seem heavyweight, ensuring we cover all of these topics before PR reviews saves us all time and helps us maintain strong code safety and quality. -->

# Summary

<!-- Describe what this PR improves along with a description of how in a sentence or two. -->

## Issue Tracking

<!-- Describe which existing tickets this PR aims to resolve by prefixing the ticket number with `Closes` in the list. For tickets or PRs which this does not close, but which are related, use the prefix `See also:` -->

- Closes #<NN>
- Closes #<MM>
- See also: #<LL>
- See also: #<KK>

## Public API Changes

<!-- Ensure that the CHANGELOG of the appropriate crate(s) document all changes to public APIs. Briefly note those changes here, indicating whether the change(s) breaks API compatibility; pay particular attention to changes to public trait interfaces, as additive changes that do not supply a default implementation are API-breaking. Also, updates to the minimum-supported Rust version, and major-version updates to dependencies that are exposed as part of the public API are considered to be API-breaking changes. Use `cargo semver-checks` to confirm whether the changes you have introduced constitute semver-breaking changes. If there are no public API impacts, assert "No API changes." here. -->

## Known Related Project Impacts

<!-- If you know this change impacts other codebases / projects, name them here. Make sure you've linked to relevant issues above in `Issue Tracking`. Also, make sure you notify the other project about this PR! If you crosslink to github PRs or Issues, that should generate a notification for them. -->

<!-- This is also a good place to mention how this change might fit into bigger / longer plans across multiple projects, e.g. "this sets the groundwork for project Foo to add their Whatsit Feature in Q3". -->

## Security & Privacy Impacts

<!-- Make your best effort guess as to the impacts this PR may have on the security or privacy of the target code bases. If you believe the changes have no impact, explicitly assert that. -->

## Usability and Performance Impacts

<!-- Your best effort guess as to potential UX / Performance impacts. If this is too speculative, because this code is too far away from end-user products to have confidence, state that too. -->

## Dependency Impacts

[ ] This PR does not alter the set of transitive dependencies or their versions.

<!-- If you can't check the above, provide a rationale for the dependency change. -->

## Local Automated Checks

I verified each of these on my system:

- [ ] cargo check
- [ ] cargo test --all-features
- [ ] cargo clippy --all-features --all-targets 
- [ ] cargo fmt
- [ ] cargo doc

### Warnings

[ ] None of the above resulted in new or altered warnings versus the target branch (e.g. `main`).
[ ] After the changes there are fewer/no warnings on my system vs the target branch.

<!-- OR: describe the change in warnings on your system and advocate for why it is necessary. -->
