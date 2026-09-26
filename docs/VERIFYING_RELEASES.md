# Verifying downloaded packages

Authenticate downloaded code before executing it. Install GitHub CLI (`gh`) from a source you trust independently of this package. Use a current version supporting all flags below; do not drop policy flags to accommodate older tooling. Node.js 22 or newer is required to run the verified client.

## Choose the source and obtain the files

1. Select the full 40-character commit you intend to trust from the source repository's protected `main`, review its changes and successful checks, and record that value independently. Do not take the expected commit only from the downloaded archive, bundle or an unsolicited message. An authentic old build can still have known vulnerabilities.
2. From that commit's successful **Verify hardened client** push run in `ffookk/ecp`, download **verified-local-client**. GitHub's download wrapper contains `ecp-local-client.tar` and `ecp-local-client.tar.sigstore.json`. Unpack only that wrapper into an empty download directory. Do not extract the inner TAR or execute package code yet. Artifacts currently expire after 14 days; an expired or unavailable package is not a reason to bypass verification.
3. The **experimental-local-client** artifact from a branch or pull request has no trusted-main attestation. Local `npm run package` also does not create one. This verification procedure must reject those unless the exact bytes separately have the required trusted-main provenance for the chosen commit.

## Verify before extracting

In the directory containing the two downloaded files, substitute the independently selected full commit below. The command uses the supplied bundle, verifies its signature and archive digest, and enforces the repository, workflow, main ref, source commit and GitHub-hosted runner identity. There is no weaker fallback.

```sh
EXPECTED_COMMIT='REPLACE_WITH_THE_TRUSTED_FULL_COMMIT'
gh attestation verify ecp-local-client.tar \
  --bundle ecp-local-client.tar.sigstore.json \
  --repo ffookk/ecp \
  --signer-workflow ffookk/ecp/.github/workflows/ci.yml \
  --source-ref refs/heads/main \
  --source-digest "$EXPECTED_COMMIT" \
  --deny-self-hosted-runners &&
mkdir ecp-verified &&
tar -xf ecp-local-client.tar -C ecp-verified &&
cd ecp-verified &&
node scripts/serve.mjs
```

The `&&` chain stops before extraction or execution if verification fails. An existing `ecp-verified` directory also stops this sequence; use a fresh empty location rather than mixing releases. Do not use elevated privileges. Open `http://127.0.0.1:4173` once the server starts. A trusted local archive built from the same exact payloads can use the CI bundle only if its complete bytes match; deterministic archive formatting alone does not prove independently reproducible builds.

Verification is performed by the independently installed CLI, not by code from the archive. The archive's `SHA256SUMS.json` files only check internal consistency; replacing the payload and its manifests does not forge this external provenance signature. Check the CLI's exit status, not a copied screenshot or a success sentence supplied with the download. Missing/broken bundles, modified archives, mismatched commits or unavailable verification services must stop this path.

## Scope and privacy

The signature establishes that the specified GitHub workflow attested these bytes for the selected source revision. It does not establish that the code or dependencies are benign, that the custom protocol is independently audited, that the selected revision is current, or that a compromised build environment is trustworthy. Protecting the GitHub account, workflow, dependencies, local verifier and device remains necessary. Verification is a point-in-time check; later filesystem modification can change the code the local server reads.

Signing publishes the package digest and public repository/workflow/commit/run metadata to GitHub and Sigstore. Public transparency records are persistent. No user vault, private signing key, passphrase, personal message, browser profile or clipboard is an input to this release process. Online verification can contact GitHub/Sigstore for trust material and exposes ordinary request metadata. Supplying `--bundle` does not by itself guarantee zero network access. Once the verified client and Node.js are obtained, serving the client locally does not require provenance services.

For verification semantics and separately managed offline trust roots, see the official [GitHub CLI verification manual](https://cli.github.com/manual/gh_attestation_verify) and [GitHub artifact attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations). Do not use an unverified trust-root file supplied by the same untrusted download as a substitute for an independent trust anchor.
