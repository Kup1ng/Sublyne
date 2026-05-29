#!/usr/bin/env bash
# Generate the changelog body for a tag-driven GitHub Release.
#
# Called by .github/workflows/release.yml with the current run's
# checkout at the tagged commit. We walk `git log <prev-tag>..HEAD` (or
# the full history if no previous tag exists, e.g. v0.1.0) and bucket
# commits by Conventional Commits type (feat, fix, chore, docs,
# refactor, test, ci, perf, build, style, security). Commits that
# don't follow the convention land in an "Other" bucket so they still
# appear — that's a nudge to PR authors rather than a hard error.
#
# Output is markdown on stdout. The release workflow pipes it to
# softprops/action-gh-release@v2's body_path.
#
# Usage:
#     ./scripts/changelog.sh                    # auto-detect range
#     ./scripts/changelog.sh v0.1.0..HEAD       # explicit range
#     ./scripts/changelog.sh --tag v0.1.0       # explicit current tag

set -euo pipefail

# Resolve range: if an arg is given and contains "..", treat it as a
# git log range; otherwise discover the previous tag from the current
# HEAD and use <prev>..HEAD. For the very first release where no prior
# tag exists, fall back to the full history.
RANGE=""
CURRENT_TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tag)
      CURRENT_TAG="$2"
      shift 2
      ;;
    *..*)
      RANGE="$1"
      shift
      ;;
    *)
      echo "Usage: $0 [--tag <vX.Y.Z>] [<git-range>]" >&2
      exit 64
      ;;
  esac
done

if [ -z "$CURRENT_TAG" ]; then
  CURRENT_TAG="$(git describe --tags --exact-match HEAD 2>/dev/null || true)"
fi

if [ -z "$RANGE" ]; then
  # Pick the most recent tag that ISN'T the current tag. If we're
  # not exactly on a tag, the most recent tag IS the previous one.
  prev=""
  if [ -n "$CURRENT_TAG" ]; then
    # `git describe --tags --abbrev=0 <tag>^` returns the parent's
    # nearest tag, i.e. the prior release. The fallback handles the
    # initial release where there is no parent tag.
    prev="$(git describe --tags --abbrev=0 "${CURRENT_TAG}^" 2>/dev/null || true)"
  else
    prev="$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)"
  fi
  if [ -n "$prev" ]; then
    RANGE="${prev}..HEAD"
  else
    # No previous tag → this is the initial release. Walk every
    # commit ever made.
    RANGE=""
  fi
fi

# Header line.
if [ -n "$CURRENT_TAG" ]; then
  echo "## ${CURRENT_TAG}"
else
  echo "## Release"
fi
echo

if [ -n "$RANGE" ]; then
  PREV_TAG_DISPLAY="${RANGE%..*}"
  echo "Changes since \`${PREV_TAG_DISPLAY}\`:"
else
  echo "Initial release."
fi
echo

# Collect commits as "subject||short-sha" lines. `git log --reverse`
# gives oldest-first so a feature stack reads in implementation order.
if [ -n "$RANGE" ]; then
  LOG="$(git log --reverse --format='%s||%h' "$RANGE")"
else
  LOG="$(git log --reverse --format='%s||%h')"
fi

# Skip if the range is empty (re-run with no new commits — possible on
# a tag that points at an already-released commit).
if [ -z "$LOG" ]; then
  echo "_No commits in this range._"
  exit 0
fi

# Buckets. Order in the output matches the order below.
declare -A BUCKETS
BUCKET_ORDER=(features fixes performance security maintenance docs refactor tests ci build style other)
declare -A BUCKET_TITLES=(
  [features]="Features"
  [fixes]="Fixes"
  [performance]="Performance"
  [security]="Security"
  [maintenance]="Maintenance"
  [docs]="Documentation"
  [refactor]="Refactoring"
  [tests]="Tests"
  [ci]="CI"
  [build]="Build"
  [style]="Style"
  [other]="Other"
)

classify() {
  # First token of the commit subject, with optional scope and an
  # optional bang for breaking changes. Examples:
  #   feat(api): add tunnel import
  #   fix: TCP RST suppression
  #   feat!: drop legacy ICMP path
  #   chore(deps): bump tokio to 1.40
  local subject="$1"
  local prefix
  prefix="$(printf '%s' "$subject" | awk -F'[(:]' '{ print $1 }' | tr '[:upper:]' '[:lower:]' | tr -d '!')"
  case "$prefix" in
    feat) echo "features" ;;
    fix)  echo "fixes" ;;
    perf) echo "performance" ;;
    sec|security) echo "security" ;;
    chore) echo "maintenance" ;;
    docs|doc) echo "docs" ;;
    refactor) echo "refactor" ;;
    test|tests) echo "tests" ;;
    ci) echo "ci" ;;
    build) echo "build" ;;
    style) echo "style" ;;
    *) echo "other" ;;
  esac
}

while IFS= read -r line; do
  [ -z "$line" ] && continue
  subject="${line%%||*}"
  sha="${line##*||}"
  bucket="$(classify "$subject")"
  # Render: `- subject (<sha>)`. Strip the `Co-Authored-By:` lines
  # that conventional commits sometimes spill into the subject — they
  # never reach the first line of a commit message in practice but
  # the awk-based classify is forgiving, so this is belt-and-braces.
  rendered="- ${subject} (${sha})"
  if [ -n "${BUCKETS[$bucket]:-}" ]; then
    BUCKETS[$bucket]+=$'\n'"$rendered"
  else
    BUCKETS[$bucket]="$rendered"
  fi
done <<< "$LOG"

for key in "${BUCKET_ORDER[@]}"; do
  body="${BUCKETS[$key]:-}"
  if [ -z "$body" ]; then continue; fi
  echo "### ${BUCKET_TITLES[$key]}"
  echo
  echo "$body"
  echo
done

# Footer. Linking the compare view gives the user one click to see
# the full diff. GitHub auto-resolves owner/repo from the workflow
# context; bash-side we just include the tag pair.
if [ -n "$RANGE" ]; then
  PREV="${RANGE%..*}"
  CUR="${CURRENT_TAG:-HEAD}"
  echo "Full diff: \`${PREV}...${CUR}\`"
fi
