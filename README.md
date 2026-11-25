# stdkit-ci-spike-0a

**Disposable Phase 0a CI proof sandbox for `stdkit` (`FS-165`).**

This repository exists solely to provide empirical live GitHub Actions evidence for `stdkit` V2 Phase 0a (`V14`, `N1`, `M1`, `pull_request_target`, `pull_request_review`, `workflow_run`, `edited` base retargeting, Rulesets, and Environments).

It contains no secrets or production code and is safe to delete after Phase 0a review (`FS-165`):
- GitHub UI: Settings -> Danger Zone -> Delete this repository
- CLI: `gh auth refresh -h github.com -s delete_repo && gh repo delete mjstrong0112/stdkit-ci-spike-0a --yes`

Phase 2 (FS-168) clean control PR.
