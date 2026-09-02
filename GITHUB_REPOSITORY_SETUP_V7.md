# BreachAtlas — GitHub Repository Setup v7.0

1. Create an empty GitHub repository named `breachatlas`; do not add a remote README/license because this folder already contains them.
2. Verify the prefilled `Parsa-Emami` GitHub namespace in CODEOWNERS/module paths; change it only if this repo will live elsewhere.
3. Push this project directory as repository root.
4. Protect `main`: PR required, `contracts` required status check, conversations resolved, signed commits if your org policy requires them, force pushes/deletions disabled.
5. Restrict allowed GitHub Actions and require full-length SHA pinning where your plan/org supports the policy.
6. Enable Dependabot alerts, secret scanning/push protection and private vulnerability reporting where available.
7. Run `make validate`, then `make bootstrap`; review all dependency manifests/lockfiles in the first source PR.

Do not enable self-hosted runners for untrusted public pull requests. Do not expose repository/environment secrets to fork PR code.
