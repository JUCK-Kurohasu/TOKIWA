#!/usr/bin/env bash
# Mirror docs/wiki/ into the repository's GitHub wiki (<owner>/<repo>.wiki.git).
#
# The wiki is generated: docs/wiki/ in the main repository is the source of truth (reviewed in pull requests),
# and this script replaces the wiki's content with it. Pages edited directly on GitHub are overwritten.
#
#   scripts/publish-wiki.sh [SOURCE_DIR]           # default SOURCE_DIR: docs/wiki
#
# Environment:
#   GITHUB_REPOSITORY  owner/repo (set by GitHub Actions; otherwise derived from the "origin" remote)
#   GITHUB_SERVER_URL  default https://github.com
#   GH_TOKEN           token allowed to push to the repository (Actions: GITHUB_TOKEN with contents: write).
#                      When unset, git's own credentials are used (handy for a manual run).
#
# Prerequisite: the wiki must exist. Enable it (Settings > General > Features > Wikis) and create any first page
# once in the web UI; GitHub only creates <repo>.wiki.git after that.
set -euo pipefail

src="${1:-docs/wiki}"
server="${GITHUB_SERVER_URL:-https://github.com}"

if [[ ! -f "$src/Home.md" ]]; then
  echo "error: $src/Home.md not found (run from the repository root or pass the wiki source directory)" >&2
  exit 1
fi

repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
  origin="$(git remote get-url origin)"
  repo="${origin#*github.com[:/]}"
  repo="${repo%.git}"
fi

git_args=()
if [[ -n "${GH_TOKEN:-}" ]]; then
  # Pass the token as a header (like actions/checkout) so it never appears in a URL, the remote config or logs.
  basic="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
  git_args=(-c "http.extraheader=AUTHORIZATION: basic $basic")
fi

rev="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo local)}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! git ${git_args[@]+"${git_args[@]}"} clone --quiet --depth 1 "$server/$repo.wiki.git" "$work/wiki"; then
  echo "error: could not clone $repo.wiki.git." >&2
  echo "       Enable the wiki (Settings > General > Features > Wikis) and create any first page once in the web UI." >&2
  exit 1
fi

# Mirror: drop everything except .git, then copy the source. README.md documents docs/wiki/ for contributors and is
# not a wiki page.
find "$work/wiki" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -R "$src"/. "$work/wiki/"
rm -f "$work/wiki/README.md"

cd "$work/wiki"
git add --all
if git diff --cached --quiet; then
  echo "wiki: already up to date"
  exit 0
fi

git -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit --quiet -m "Sync from ${repo}@${rev} (docs/wiki)"
git ${git_args[@]+"${git_args[@]}"} push --quiet origin HEAD
echo "wiki: published $(git diff --stat HEAD~1 HEAD | tail -n 1)"
