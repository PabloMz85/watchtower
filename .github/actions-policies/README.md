# GitHub Actions execution policies

These JSON files are the reviewed repository-policy request bodies for
`PabloMz85/watchtower`. They are versioned in PR #29 together with the coverage
change. **GitHub does not load or activate these files from a branch or a merged
PR.** A repository administrator must apply them through Settings → Actions →
Policies or the official repository Actions policy REST API.

## Scope

| Manifest | Exact workflow | Allowed events |
| --- | --- | --- |
| `pull-request.json` | `.github/workflows/pull-request.yml` | `pull_request`, `workflow_dispatch` |
| `codeql.json` | `.github/workflows/codeql-analysis.yml` | `pull_request`, `push`, `schedule`, `workflow_dispatch` |
| `dependabot.json` | `.github/workflows/dependabot-approve.yml` | `pull_request_target` |

Each policy is active and targets one exact workflow path, without wildcards or
repository-wide workflow selectors. Its actor allowlist contains only:

- `PabloMz85`: GitHub user ID `19808080`, actor type `User`.
- `dependabot[bot]`: GitHub user ID `49699333`, actor type `Bot`.

Both identities were checked against GitHub before preparing the manifests.
Other actors are not authorized by these policies. An actor's repository write
access does not bypass this explicit allowlist. Revisit it deliberately if the
maintainer list or automation identities change.

Policy scope is **repository-wide for each named workflow**, not limited to the
PR or branch containing these manifests. Workflow event filters, job conditions,
fork protections and token permissions remain separate controls. Applicable
organization or enterprise restrictions still apply; a repository policy cannot
override them.

## Security boundaries

- CI continues using `pull_request`, not `pull_request_target`. The latter event
  is allowed only for the existing metadata-only Dependabot workflow, which does
  not check out or execute PR code. Its job still checks the Dependabot actor;
  allowing the owner through execution policy lets non-Dependabot runs reach
  that existing skip condition.
- These policies do not grant token scopes, expose secrets, authorize automatic
  reviews, or enable workflow dispatch on a workflow that does not declare it.
  In particular, they do not enable the separate repository option allowing
  GitHub Actions to approve pull requests. That option is an independent owner
  decision, not a side effect of these manifests.
- No policy targets release, image publication, documentation or greeting
  workflows. Development image publication remains manual, and no release is
  dispatched by applying these policies.
- Keep the repository's existing read-only default workflow token permissions.
  Do not disable execution protections or create a global event exception to
  make CI start.

## Applying and verifying changes

The files use the request shape for `POST /repos/{owner}/{repo}/actions/policies`
with GitHub REST API version `2026-03-10`. For an existing policy, review its full
current definition and update that exact policy ID with `PUT` rather than creating
a duplicate. Preserve unrelated policies, and inspect inherited policies before
changing a repository's policy set. In particular, a policy with zero matching
workflows or an empty allowlist is not an equivalent replacement.

Use an existing administrator session or approved credential manager; never put
credentials in these files or in a PR workflow. After an API write, read the
exact policy ID back and compare `name`, `enforcement`, `conditions`, and `rules`
with the reviewed request. Verify the ordinary Actions settings and default token
permissions remain unchanged.

Finally, trigger the existing PR validation on the intended head and inspect the
actual jobs and coverage upload. A successful policy write or a local test does
not establish a successful GitHub Actions run. Check Codecov receipt for the
same commit before claiming a new hosted patch-coverage result.

## References

- [Actions policy concepts](https://docs.github.com/en/actions/concepts/about-actions-policies)
- [Workflow execution governance](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution)
- [Repository Actions policy REST API](https://docs.github.com/en/rest/actions/policies#create-a-repository-actions-policy)
- [Security of `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
