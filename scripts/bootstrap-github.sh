#!/usr/bin/env bash
# bootstrap-github.sh — one-shot setup for the pgsleuth repo + project + issues.
#
# Prerequisites:
#   - gh CLI installed and authenticated as a user with rights in tarqwork
#       (run `gh auth status` to confirm)
#   - Run from inside the pgsleuth repo root (this directory should contain
#       this script under scripts/, plus README.md, tasks.md, etc.)
#
# What this does:
#   1. Initializes the local git repo if not already done
#   2. Creates the GitHub repo at tarqwork/pgsleuth (public)
#   3. Pushes the initial commit
#   4. Creates a GitHub Project (org-level) titled "pgsleuth"
#   5. Parses tasks.md and creates one issue per task, adds each to the project
#
# Idempotency: re-running is mostly safe — the script checks before creating
# repos/projects. Issues are created fresh on each run, so don't run it twice
# unless you want duplicates. If you need to re-run, delete the issues first
# or remove the [issue creation] section.

set -euo pipefail

ORG="tarqwork"
REPO="pgsleuth"
PROJECT_TITLE="pgsleuth"
DEFAULT_BRANCH="main"

# ─── Sanity checks ─────────────────────────────────────────────────────────

if ! command -v gh &>/dev/null; then
    echo "ERROR: gh CLI not found. Install: https://cli.github.com" >&2
    exit 1
fi

if ! gh auth status &>/dev/null; then
    echo "ERROR: gh CLI not authenticated. Run: gh auth login" >&2
    exit 1
fi

if [[ ! -f README.md || ! -f tasks.md ]]; then
    echo "ERROR: run this script from the pgsleuth repo root." >&2
    echo "Expected to find README.md and tasks.md in the current directory." >&2
    exit 1
fi

echo "==> Authenticated as: $(gh api user --jq .login)"
echo "==> Will create:      ${ORG}/${REPO} (public)"
echo "==> Will create:      project '${PROJECT_TITLE}' under org ${ORG}"
echo
read -r -p "Proceed? [y/N] " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# ─── 1. Local git ──────────────────────────────────────────────────────────

if [[ ! -d .git ]]; then
    echo "==> Initializing local git repo"
    git init -b "${DEFAULT_BRANCH}"
    git add .
    git -c user.useConfigOnly=false commit -m "chore: initial skeleton

- Apache 2.0 licensed
- Cargo workspace: pgsleuth-core, -postgres, -otel, -cli
- Python brain (pgsleuth-brain) — pre-alpha scaffold
- Unified Makefile (Rust + Python dev/test/lint)
- GitHub Actions CI for both stacks
- docs/design/000-architecture.md — foundational design doc
- docs/research/ — phase 0 spike placeholders
- tasks.md — week 0/1/long-term tasks (source of truth for the Project)

Pre-alpha. Building in public. No public advertising before v0.2."
else
    echo "==> Local git repo already initialized; skipping init"
fi

# ─── 2. GitHub repo ────────────────────────────────────────────────────────

if gh repo view "${ORG}/${REPO}" &>/dev/null; then
    echo "==> Repo ${ORG}/${REPO} already exists; skipping create"
    # Make sure remote is set
    if ! git remote get-url origin &>/dev/null; then
        git remote add origin "https://github.com/${ORG}/${REPO}.git"
    fi
else
    echo "==> Creating ${ORG}/${REPO} on GitHub"
    gh repo create "${ORG}/${REPO}" \
        --public \
        --source=. \
        --remote=origin \
        --description "Postgres observability that thinks like a senior DBA. Local-first, OTel-native, no lock-in. Pre-alpha." \
        --push
fi

# Push (no-op if everything is up to date)
git push -u origin "${DEFAULT_BRANCH}" 2>/dev/null || true

# ─── 3. GitHub Project (org-level, ProjectV2) ──────────────────────────────

# Check if a project with this title already exists for the org
EXISTING_PROJECT=$(gh project list --owner "${ORG}" --format json --jq \
    ".projects[] | select(.title == \"${PROJECT_TITLE}\") | .number" 2>/dev/null || true)

if [[ -n "${EXISTING_PROJECT}" ]]; then
    PROJECT_NUMBER="${EXISTING_PROJECT}"
    echo "==> Project '${PROJECT_TITLE}' already exists (#${PROJECT_NUMBER}); reusing"
else
    echo "==> Creating project '${PROJECT_TITLE}' under ${ORG}"
    PROJECT_NUMBER=$(gh project create --owner "${ORG}" --title "${PROJECT_TITLE}" \
        --format json --jq .number)
    echo "==> Created project #${PROJECT_NUMBER}"
fi

# ─── 4. Parse tasks.md and create issues ──────────────────────────────────

echo "==> Parsing tasks.md"

# Use awk to split tasks.md into one task per record. Each task is:
#   ### TASK: <title>
#   **Labels:** label1, label2
#   <body>
# (until the next ### TASK: heading or a single line containing only "---")

python3 - <<'PYEOF' > /tmp/pgsleuth-tasks.tsv
import re
import pathlib

content = pathlib.Path("tasks.md").read_text()

# Split on the task heading. We get [preamble, title1, body1, title2, body2, ...]
parts = re.split(r"^### TASK:\s*(.+)$", content, flags=re.MULTILINE)
preamble = parts[0]
tasks = list(zip(parts[1::2], parts[2::2], strict=True))

for title, body in tasks:
    title = title.strip()
    body = body.strip()

    # Extract labels line
    labels = ""
    label_match = re.search(r"^\*\*Labels:\*\*\s*(.+)$", body, flags=re.MULTILINE)
    if label_match:
        labels = label_match.group(1).strip()
        # Remove the labels line from the body
        body = re.sub(r"^\*\*Labels:\*\*.*$\n?", "", body, count=1, flags=re.MULTILINE).strip()

    # Stop body at the next "---" or "## " section
    body = re.split(r"^---\s*$|^## ", body, flags=re.MULTILINE)[0].strip()

    # TSV: title \t labels \t body (body has \n escaped)
    body_escaped = body.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "    ")
    print(f"{title}\t{labels}\t{body_escaped}")
PYEOF

TASK_COUNT=$(wc -l < /tmp/pgsleuth-tasks.tsv | tr -d ' ')
echo "==> Found ${TASK_COUNT} tasks. Creating issues and adding to project #${PROJECT_NUMBER}"

# Pre-create labels so issue creation doesn't fail on unknown labels
declare -A SEEN_LABELS
while IFS=$'\t' read -r title labels body; do
    IFS=',' read -ra LABEL_ARR <<< "${labels}"
    for label in "${LABEL_ARR[@]}"; do
        label="$(echo "${label}" | xargs)"  # trim
        [[ -z "${label}" ]] && continue
        if [[ -z "${SEEN_LABELS[${label}]:-}" ]]; then
            SEEN_LABELS[${label}]=1
            # Create label if missing (ignore failure if it already exists)
            gh label create "${label}" --repo "${ORG}/${REPO}" --color BFD4F2 2>/dev/null || true
        fi
    done
done < /tmp/pgsleuth-tasks.tsv

# Create one issue per task, add to project
while IFS=$'\t' read -r title labels body; do
    # Unescape body
    body_unescaped="$(echo -e "${body//\\n/\\n}")"

    # Build label flags
    label_args=()
    IFS=',' read -ra LABEL_ARR <<< "${labels}"
    for label in "${LABEL_ARR[@]}"; do
        label="$(echo "${label}" | xargs)"
        [[ -z "${label}" ]] && continue
        label_args+=(--label "${label}")
    done

    echo "  - Creating issue: ${title}"
    issue_url=$(gh issue create \
        --repo "${ORG}/${REPO}" \
        --title "${title}" \
        --body "${body_unescaped}" \
        "${label_args[@]}")

    # Add the issue to the project
    gh project item-add "${PROJECT_NUMBER}" --owner "${ORG}" --url "${issue_url}" >/dev/null
done < /tmp/pgsleuth-tasks.tsv

rm -f /tmp/pgsleuth-tasks.tsv

echo
echo "==> Done."
echo "    Repo:    https://github.com/${ORG}/${REPO}"
echo "    Project: https://github.com/orgs/${ORG}/projects/${PROJECT_NUMBER}"
echo
echo "Next: 'gh project view ${PROJECT_NUMBER} --owner ${ORG} --web' to open the project."
