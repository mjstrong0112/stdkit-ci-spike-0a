The code, tests, and checks are the source of truth. If this file disagrees with them, follow the code and checks, and flag the drift in your PR.

# Agent guidance

Precedence: code and checks, then accepted ADRs, then this file, then plans and tickets.

<!-- stdkit:begin team-guidance -->
## Team standards

- Trace the relevant behavior and choose the smallest complete change.
- Validate inputs at trust boundaries and preserve the cause of errors.
- For a bug fix or specified behavior, write a failing test first.
- Run the repository's relevant checks and report what passed.
- Keep secrets and personal data out of fixtures, reports, and commits.
- Keep changes focused and update the owning documentation when behavior changes.
<!-- stdkit:end team-guidance -->

<!-- alt-base divergence for S7b -->
