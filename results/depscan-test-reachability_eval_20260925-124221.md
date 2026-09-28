# depscan evaluation: depscan-test-reachability

- result: `results/depscan-test-reachability_20260925-123947.json`
- expected: `~/depscan-test-reachability/.depscan/expected.yaml`
- generated: 2026-09-25 12:42 UTC

## Summary

| mode | accuracy | correct / scored | answered uncertain | not run |
|---|---|---|---|---|
| without context | n/a | 0 / 0 | 0 of 0 (n/a) | 15 |
| with context | n/a | 0 / 0 | 0 of 0 (n/a) | 15 |

Accuracy counts only advisories labelled likely_affected / likely_not_affected; `uncertain` answers on those count as wrong.

## Advisories

| id | package | scenario | expected | without context | with context |
|---|---|---|---|---|---|
| CVE-2020-14343 | pyyaml | reachable_untrusted_input | likely_affected | not_run – | not_run – |
| CVE-2026-45409 | idna | reachable_untrusted_input | likely_affected | not_run – | not_run – |
| CVE-2024-22195 | jinja2 | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2024-34064 | jinja2 | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2024-56201 | jinja2 | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2024-56326 | jinja2 | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2025-27516 | jinja2 | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2023-32681 | requests | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2024-35195 | requests | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2024-47081 | requests | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2026-25645 | requests | imported_feature_unused | likely_not_affected | not_run – | not_run – |
| CVE-2022-40896 | pygments | vulnerable_call_only_in_tests | likely_not_affected | not_run – | not_run – |
| CVE-2026-4539 | pygments | vulnerable_call_only_in_tests | likely_not_affected | not_run – | not_run – |
| CVE-2024-34062 | tqdm | dev_only_dependency | likely_not_affected | not_run – | not_run – |
| CVE-2020-25658 | rsa | declared_never_imported | likely_not_affected | not_run – | not_run – |

## Confusion matrix (without context)

| expected \ predicted | likely_affected | likely_not_affected | uncertain | not_run |
|---|---|---|---|---|
| likely_affected | 0 | 0 | 0 | 2 |
| likely_not_affected | 0 | 0 | 0 | 13 |
| uncertain | 0 | 0 | 0 | 0 |

## Confusion matrix (with context)

| expected \ predicted | likely_affected | likely_not_affected | uncertain | not_run |
|---|---|---|---|---|
| likely_affected | 0 | 0 | 0 | 2 |
| likely_not_affected | 0 | 0 | 0 | 13 |
| uncertain | 0 | 0 | 0 | 0 |

## Per scenario

| scenario | without context | with context |
|---|---|---|
| declared_never_imported | n/a (0/0) | n/a (0/0) |
| dev_only_dependency | n/a (0/0) | n/a (0/0) |
| imported_feature_unused | n/a (0/0) | n/a (0/0) |
| reachable_untrusted_input | n/a (0/0) | n/a (0/0) |
| vulnerable_call_only_in_tests | n/a (0/0) | n/a (0/0) |
