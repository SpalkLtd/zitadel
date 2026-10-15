# Spalk fork of Zitadel

This fork adds a v2 `MoveUser` API (`zitadel.user.v2.UserService/MoveUser`) that moves a human user to another organisation, keeping their ID, credentials, MFA, passkeys and IdP links. Spalk needs it because upstream Zitadel can't change a user's organisation.

- **Branch:** `spalk` (this fork's default branch), rebased on an upstream release tag (currently `v4.19.4`).
- **Tags and images:** `v<upstream version>-spalk.<n>`, e.g. `v4.19.4-spalk.1`. The manually run **Spalk publish image** workflow (`.github/workflows/spalk-publish.yml`) calls `.github/workflows/spalk-publish-image.yml` at a pinned commit, which builds the image on GitHub's arm64 runner and pushes it, with upstream's login UI image, to Spalk's private ECR. Spalk's AWS role trusts only that file at the commits spalk-stack lists in `publish_workflow_shas`.
- **Go SDK:** [SpalkLtd/zitadel-go](https://github.com/SpalkLtd/zitadel-go) adds the `MoveUser` client.
- **Upstream workflows:** disable them in this fork's Actions settings; they need Zitadel's own runners and secrets.
- **How Spalk deploys it:** `docs/infra/zitadel-fork.md` in Spalk's monorepo.
