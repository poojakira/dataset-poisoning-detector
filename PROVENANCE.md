# Repository Provenance Audit

## Decision

**Earliest defensible year for this repository/project lineage: 2026**

**Earliest reachable commit on `main`:** 2026-07-11  
**Commit:** [`f70842e3fdc9`](https://github.com/poojakira/dataset-poisoning-detector/commit/f70842e3fdc9add16a0a02204a1a6f2ccc986688)  
**Commit message:** `Initial commit`

## Evidence standard

This audit separates three different things:

1. **Git repository inception** — the earliest reachable commit on the default branch.
2. **Pre-Git source lineage** — accepted only when a dated artifact clearly refers to the same project or an identifiable direct precursor.
3. **Background dates** — course years, publication years, CVE/incident dates, dataset dates, framework versions, test timestamps, and copied changelog labels do **not** backdate a repository unless they directly prove the project's own existence.

Git history is preserved as historical evidence. It is not rewritten or backdated from later documents.

## Findings

- The changelog originally labeled versions 0.1.0 and 0.2.0 as January 2024. Commit history shows CHANGELOG.md was first added on 2026-07-11; those unsupported dates were corrected in commit 62f8555727dbea8af63c4c4131913e3e327cf1a4.

## Provenance conclusion

The evidence reviewed supports **2026** as the earliest defensible year for this repository. Earlier dates may exist in referenced research, source datasets, publications, standards, or unrelated/precursor academic work, but no direct evidence reviewed here justifies rewriting this repository's Git history to an earlier year.

## Audit scope

Evidence considered in this pass included:

- reachable Git commit history on `main`;
- repository README, changelog, reports, and documentation;
- date-like labels in high-visibility files;
- course/project references where present;
- connected Drive metadata/search for exact or closely related project names;
- previously verified academic/publication evidence, used only as background unless a direct lineage could be established.

**Audit date:** 2026-09-21


## Expanded proof matrix

| Evidence source | What was checked | Result |
|---|---|---|
| Reachable Git history | Earliest reachable commit on `main` | **2026-07-11** — [`f70842e3fdc9`](https://github.com/poojakira/dataset-poisoning-detector/commit/f70842e3fdc9add16a0a02204a1a6f2ccc986688) — `Initial commit` |
| Repository files/docs | README, changelog, reports, embedded date labels, provenance files, and high-visibility docs | No dated file reviewed establishes this repository or a clearly identifiable direct precursor before **2026**. |
| Course/project references | Course codes, academic project references, publication links, and research-period references present in or connected to the repository | No course/publication reference reviewed proves this repository existed before **2026**. Earlier academic work remains a separate provenance track unless direct lineage is documented. |
| Internal evidence | Repository-local evidence files and previously audited connected-source metadata | Supports the documented 2026 development/research period; no direct pre-2026 same-project artifact was established. |
| Commit identity/history integrity | Historical author/committer objects and existing timestamps | Preserved as-is. No commits were backdated, timestamp-rewritten, or replaced to manufacture an older timeline. |

### Repository-specific evidence notes

- The changelog originally labeled versions 0.1.0 and 0.2.0 as January 2024. Commit history shows CHANGELOG.md was first added on 2026-07-11; those unsupported dates were corrected in commit 62f8555727dbea8af63c4c4131913e3e327cf1a4.

### Provenance confidence

**High for the mapped year (2026).** The reachable Git history is direct evidence. Any earlier year would require a dated source artifact that can be tied to this exact repository or a clearly identifiable direct precursor.

### History policy

This audit records provenance **without rewriting Git history**. If stronger pre-Git evidence is discovered later, document it as pre-Git lineage with the artifact date and source; do not alter historical commit timestamps.
