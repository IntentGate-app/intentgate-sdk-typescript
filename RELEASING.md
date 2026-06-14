# Releasing @intentgate-app/intentgate

Maintainer-facing notes for cutting a release. Consumers should read [`README.md`](README.md).

## One-time npm setup (trusted publishing)

The release workflow at [`.github/workflows/release.yml`](.github/workflows/release.yml) is wired for **OIDC trusted publishing** — every tag push produces a publish with `--provenance` attestation and no `NPM_TOKEN` secret needs to exist anywhere. Mirrors the Python SDK's PyPI flow.

Three things need to be true on npmjs.com once, before the first release:

1. **Reserve the `@intentgate-app` org.** Sign in to npmjs.com, go to *Add organization*, choose the name `intentgate-app`, pick the free plan. Org names are first-come; pick this before any of the SDK release rehearsals.

2. **Create the package shell.** First publish of a scoped package needs `--access public` (the workflow does this), but the package name `@intentgate-app/intentgate` must not already be squatted. Quick check:

   ```sh
   npm view @intentgate-app/intentgate
   # expect: npm error code E404 (good — name is free)
   ```

3. **Configure the trusted publisher.** This is the actual OIDC wire-up. On the package's settings page (or, since the package doesn't exist yet, in the org-level *Trusted Publishers* settings), add:

   - **Publisher**: `GitHub Actions`
   - **Organization or user**: `IntentGate-app`
   - **Repository**: `intentgate-sdk-typescript`
   - **Workflow filename**: `release.yml`
   - **Environment name**: `npm`

   The `environment.name: npm` line in the workflow has to match this exactly — that's how npm scopes which workflow run is allowed to claim a publish on this package.

After all three are in place, `npm view @intentgate-app/intentgate --json` still 404s (the package hasn't been published yet) but the publisher is registered and the next workflow run will succeed.

### Verify the OIDC plumbing without publishing

You can dry-run the trusted-publishing handshake without actually shipping a release by running the workflow on a throwaway tag:

```sh
# From a maintainer's local clone with push access:
git tag v0.1.0-rc.0
git push origin v0.1.0-rc.0
```

The workflow validates `package.json` matches the tag, runs the full lint/test/build gate, then attempts `npm publish --provenance --access public`. If the trusted-publisher config is correct, the publish succeeds and you can immediately `npm unpublish @intentgate-app/intentgate@0.1.0-rc.0` to clean up. If the OIDC handshake fails, the publish step errors with a 401 referencing the trusted-publisher mismatch — fix the npm-side config and retry.

## Cutting a real release

1. Update `package.json`'s `version` field on a feature branch.
2. Open + merge a PR that includes the version bump plus the release notes (CHANGELOG.md if you've started one).
3. From `main`:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

The release workflow does the rest: typecheck + lint + test + build + verify-version-matches-tag + publish-to-npm-with-provenance. Output appears at:

- npm: https://www.npmjs.com/package/@intentgate-app/intentgate
- workflow run: https://github.com/IntentGate-app/intentgate-sdk-typescript/actions/workflows/release.yml
- provenance attestation: visible on the package's npm page once the publish lands

## Why OIDC instead of NPM_TOKEN

- **No long-lived secret to rotate.** Every publish gets a fresh OIDC token, exchanged with npm at workflow run time, valid for that one publish.
- **Provenance is automatic.** `--provenance` attaches a SLSA-shaped attestation that links the published tarball to the exact commit SHA, workflow file, and runner that produced it. Consumers and registries can verify the supply chain without trusting us.
- **One less GitHub secret.** `NPM_TOKEN` was the last secret that would have lived on `IntentGate-app/intentgate-sdk-typescript`. Now there's nothing to leak.

Same pattern, same rationale, as the [Python SDK's PyPI trusted publishing](https://github.com/IntentGate-app/intentgate-sdk-python/blob/main/.github/workflows/release.yml) shipped session 11.
