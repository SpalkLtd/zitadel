# Spalk fork of Zitadel

This fork adds a v2 `MoveUser` API (`zitadel.user.v2.UserService/MoveUser`) that moves a human user to another organisation, keeping their ID, credentials, MFA, passkeys and IdP links. Spalk needs it because upstream Zitadel can't change a user's organisation.

It also patches the login UI (`apps/login`): a user with both a password and a linked IdP gets the password page instead of being sent straight to the IdP, and the password and passkey pages offer the organisation's active IdPs below their form. Users with only an IdP are still redirected to it. The changes are marked `// Spalk:` in `src/lib/server/loginname.ts`, `src/app/(login)/password/page.tsx` and `src/app/(login)/passkey/page.tsx`.

- **Branch:** `spalk` (this fork's default branch), rebased on an upstream release tag (currently `v4.19.4`).
- **Tags and images:** `v<upstream version>-spalk.<n>`, e.g. `v4.19.4-spalk.1`. The manually run **Spalk publish image** workflow (`.github/workflows/spalk-publish.yml`) calls `.github/workflows/spalk-publish-image.yml` at a pinned commit, which builds the API image and the login UI image (from `apps/login`, as upstream's `pack.yml` does) on GitHub's arm64 runner and pushes both, tagged with the fork's tag, to Spalk's private ECR. Spalk's AWS role trusts only that file at the commits spalk-stack lists in `publish_workflow_shas`.
- **Go SDK:** [SpalkLtd/zitadel-go](https://github.com/SpalkLtd/zitadel-go) adds the `MoveUser` client.
- **Upstream workflows:** disable them in this fork's Actions settings; they need Zitadel's own runners and secrets.
- **How Spalk deploys it:** `docs/infra/zitadel-fork.md` in Spalk's monorepo.
