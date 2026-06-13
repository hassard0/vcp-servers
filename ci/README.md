# CI

`conformance.yml` is a ready-to-use GitHub Actions workflow that runs all four
language test suites (and a vector-drift check) on every push and PR.

It lives here, rather than in `.github/workflows/`, only because it was committed
through an OAuth token without the `workflow` scope. **To enable it**, move it into
place:

```sh
mkdir -p .github/workflows
git mv ci/conformance.yml .github/workflows/conformance.yml
git commit -m "ci: enable conformance workflow"
git push
```

If your local `gh`/git token also lacks the `workflow` scope, either add the file
through the GitHub web UI (**Add file → Create new file** at
`.github/workflows/conformance.yml`, paste the contents), or refresh the scope:

```sh
gh auth refresh -s workflow
```

The workflow matrix: `vectors` (regenerate and assert no drift), `typescript`,
`python`, `go`, `rust`. The Go job is what verifies the Go reference, which was
authored without a local Go toolchain.
