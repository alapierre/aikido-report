#!/usr/bin/env bash
# =============================================================================
# Aikido vulnerability gate — Bitbucket Pipelines
# =============================================================================
# Wywołanie z pipeline:
#   . ./image.env          # IMAGE + VERSION z kroku jib:build
#   bash scripts/aikido-gate.sh "$IMAGE" "$VERSION"
#
# Kroki (wysoki poziom):
#   1. Walidacja wejścia (credentials, argumenty, curl/jq)
#   2. Rozbicie IMAGE na short name + registry
#   3. OAuth — pobranie access_token
#   4. Oczekiwanie na skan tej wersji (poll):
#        4a. lista repo w Aikido (name + registry)
#        4b. czy last_scanned_tag == VERSION?
#        4c. jeśli nie — raz trigger POST /containers/{id}/scan
#        4d. sleep i powtórz aż do timeoutu
#   5. Pobranie otwartych High/Critical
#   6. Soft-fail: exit 1 przy High/Critical / braku skanu → step czerwony w UI,
#      ale pipeline ma on-fail: ignore i NIE blokuje kolejnych kroków
# =============================================================================
set -euo pipefail

# --- Konfiguracja z env (sekrety z Repository variables) ---------------------
AIKIDO_BASE="${AIKIDO_APP_BASE:-https://app.aikido.dev}"
AIKIDO_BASE="${AIKIDO_BASE%/}"
CLIENT_ID="${AIKIDO_CLIENT_ID:-}"
CLIENT_SECRET="${AIKIDO_CLIENT_SECRET:-}"
TIMEOUT_MS="${AIKIDO_WAIT_TIMEOUT_MS:-600000}"       # max czekania na skan (10 min)
POLL_INTERVAL_MS="${AIKIDO_POLL_INTERVAL_MS:-15000}" # odstęp między pollami (15 s)

# --- Argumenty: pełna nazwa obrazu + tag z builda ---------------------------
IMAGE_ARG="${1:-}"   # np. itrustksef.azurecr.io/itrust-ksef-integration-azure
TAG_ARG="${2:-}"     # np. 2.134.0

# =============================================================================
# KROK 1: Walidacja wejścia
# =============================================================================
if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  echo "Missing AIKIDO_CLIENT_ID or AIKIDO_CLIENT_SECRET." >&2
  exit 2
fi

if [[ -z "$IMAGE_ARG" || -z "$TAG_ARG" ]]; then
  echo "Usage: scripts/aikido-gate.sh <image-name> <tag>" >&2
  exit 2
fi

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 2
  fi
done

# =============================================================================
# KROK 2: Rozbicie IMAGE → SHORT_NAME + REGISTRY
# Aikido trzyma name bez registry (np. itrust-ksef-integration-azure),
# a registry_name osobno (np. itrustksef.azurecr.io).
# =============================================================================
SHORT_NAME="${IMAGE_ARG##*/}"
REGISTRY=""
if [[ "$IMAGE_ARG" == */* ]]; then
  first="${IMAGE_ARG%%/*}"
  if [[ "$first" == *.* ]]; then
    REGISTRY="$(printf '%s' "$first" | tr '[:upper:]' '[:lower:]')"
  fi
fi

# --- Helpers HTTP / czas ----------------------------------------------------

sleep_ms() {
  local ms="$1"
  awk -v ms="$ms" 'BEGIN { printf "%.3f\n", ms / 1000 }' | xargs sleep
}

build_container_url() {
  local id="${1:-}"
  if [[ -n "$id" ]]; then
    printf '%s/container/%s\n' "$AIKIDO_BASE" "$id"
  else
    printf '%s/container\n' "$AIKIDO_BASE"
  fi
}

# =============================================================================
# KROK 3: OAuth (client credentials) → access_token
# POST /api/oauth/token  (Basic auth: client_id:client_secret)
# =============================================================================
get_access_token() {
  local basic body token
  basic="$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 | tr -d '\n')"
  body="$(
    curl -sS -X POST "${AIKIDO_BASE}/api/oauth/token" \
      -H "Authorization: Basic ${basic}" \
      -H "Content-Type: application/json" \
      -d '{"grant_type":"client_credentials"}'
  )"
  token="$(printf '%s' "$body" | jq -r '.access_token // empty')"
  if [[ -z "$token" ]]; then
    echo "Aikido OAuth failed: ${body}" >&2
    exit 1
  fi
  printf '%s\n' "$token"
}

# GET z Bearer tokenem; dodatkowe argumenty to query params w formie key=value
aikido_get() {
  local token="$1"
  local path="$2"
  shift 2

  local url="${AIKIDO_BASE}${path}"
  local sep="?"
  local key value tmp status
  for arg in "$@"; do
    key="${arg%%=*}"
    value="${arg#*=}"
    url="${url}${sep}$(printf '%s' "$key" | jq -sRr @uri)=$(printf '%s' "$value" | jq -sRr @uri)"
    sep="&"
  done

  tmp="$(mktemp)"
  status="$(
    curl -sS -o "$tmp" -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" \
      -H "Accept: application/json" \
      "$url"
  )"

  if [[ "$status" != "200" ]]; then
    echo "Aikido API ${path} failed (HTTP ${status}): $(head -c 400 "$tmp")" >&2
    rm -f "$tmp"
    exit 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

# POST bez body (używane do triggera skanu)
aikido_post() {
  local token="$1"
  local path="$2"
  local tmp status
  tmp="$(mktemp)"
  status="$(
    curl -sS -o "$tmp" -w '%{http_code}' -X POST \
      -H "Authorization: Bearer ${token}" \
      -H "Accept: application/json" \
      "${AIKIDO_BASE}${path}"
  )"

  if [[ "$status" != "200" && "$status" != "201" && "$status" != "202" && "$status" != "204" ]]; then
    echo "Aikido API ${path} failed (HTTP ${status}): $(head -c 400 "$tmp")" >&2
    rm -f "$tmp"
    exit 1
  fi

  cat "$tmp"
  rm -f "$tmp"
}

# Odpowiedź /containers bywa tablicą albo obiektem z .containers/.data/.items
normalize_containers() {
  jq -c '
    if type == "array" then .
    elif (.containers | type) == "array" then .containers
    elif (.data | type) == "array" then .data
    elif (.items | type) == "array" then .items
    else []
    end
  '
}

# -----------------------------------------------------------------------------
# KROK 4a (helper): zostaw tylko repo z exact name + registry
# -----------------------------------------------------------------------------
filter_exact_repo() {
  local containers_json="$1"
  printf '%s' "$containers_json" | jq -c \
    --arg name "$SHORT_NAME" \
    --arg registry "$REGISTRY" '
      [.[]
        | select((.name // "") == $name)
        | select(
            ($registry == "")
            or (((.registry_name // "") | ascii_downcase) == $registry)
          )
      ]
    '
}

# GET /containers?filter_name=<short> → filtr name+registry
list_repos() {
  local token="$1"
  local data
  data="$(
    aikido_get "$token" "/api/public/v1/containers" \
      "filter_name=${SHORT_NAME}" \
      "filter_status=all" \
      "per_page=100"
  )"
  filter_exact_repo "$(printf '%s' "$data" | normalize_containers)"
}

# -----------------------------------------------------------------------------
# KROK 4b: czy wśród repo jest już skan naszej VERSION?
# (Aikido: last_scanned_tag, nie osobny rekord per tag)
# -----------------------------------------------------------------------------
pick_scanned() {
  local repos_json="$1"
  local tag="$2"
  printf '%s' "$repos_json" | jq -c --arg tag "$tag" '
    [.[]
      | select((.last_scanned_tag // "") | ascii_downcase == ($tag | ascii_downcase))
      | select(.is_empty != true)
    ]
    | .[0] // empty
  '
}

# Repo do ad-hoc skanu (gdy VERSION jeszcze nie zeskanowana)
pick_for_scan() {
  local repos_json="$1"
  printf '%s' "$repos_json" | jq -c '
    [.[] | select(.is_empty != true)]
    | .[0] // empty
  '
}

# -----------------------------------------------------------------------------
# KROK 4c: trigger ad-hoc skanu
# POST /api/public/v1/containers/{id}/scan
# (API nie przyjmuje tagu — skanuje aktualny obraz w tym repo)
# -----------------------------------------------------------------------------
trigger_scan() {
  local token="$1"
  local container_json="$2"
  local container_id registry

  container_id="$(printf '%s' "$container_json" | jq -r '.id // .container_repo_id // empty')"
  registry="$(printf '%s' "$container_json" | jq -r '.registry_name // "unknown registry"')"

  if [[ -z "$container_id" ]]; then
    echo "Cannot trigger Aikido scan: missing container id." >&2
    exit 1
  fi

  echo "No scan for requested tag yet — triggering Aikido scan for container ${container_id} (${registry})..." >&2
  aikido_post "$token" "/api/public/v1/containers/${container_id}/scan" >/dev/null
  echo "Aikido scan triggered." >&2
}

# =============================================================================
# KROK 4: Poll aż last_scanned_tag == VERSION (albo timeout)
# =============================================================================
wait_for_scan() {
  local token="$1"
  local tag="$2"

  local deadline now repos match repo seen_tags
  deadline=$(( $(date +%s) * 1000 + TIMEOUT_MS ))
  local scan_triggered=0

  while true; do
    now=$(( $(date +%s) * 1000 ))
    if (( now > deadline )); then
      break
    fi

    # 4a — lista repo name+registry
    repos="$(list_repos "$token")"

    # 4b — czy skan VERSION już jest?
    match="$(pick_scanned "$repos" "$tag")"
    if [[ -n "$match" && "$match" != "null" ]]; then
      printf '%s\n' "$match"
      return 0
    fi

    # 4c — jeden raz odpal skan ad-hoc
    if [[ "$scan_triggered" -eq 0 ]]; then
      repo="$(pick_for_scan "$repos")"
      if [[ -z "$repo" || "$repo" == "null" ]]; then
        echo "No Aikido container repository found for ${SHORT_NAME}" \
          "${REGISTRY:+(registry ${REGISTRY})}." >&2
        return 1
      fi
      trigger_scan "$token" "$repo"
      scan_triggered=1
    fi

    # 4d — log + czekaj i spróbuj ponownie
    seen_tags="$(
      printf '%s' "$repos" \
        | jq -r '[.[].last_scanned_tag | select(. != null and . != "")] | unique | join(", ")'
    )"
    echo -n "Aikido scan not ready for ${IMAGE_ARG}:${tag}." >&2
    if [[ -n "$seen_tags" ]]; then
      echo -n " Current last_scanned_tag values: ${seen_tags}." >&2
    fi
    echo " Retrying in $(( POLL_INTERVAL_MS / 1000 ))s..." >&2

    sleep_ms "$POLL_INTERVAL_MS"
  done

  return 1
}

# =============================================================================
# KROK 5: Otwarte podatności High/Critical dla znalezionego kontenera
# GET /api/public/v1/issues/export
# =============================================================================
get_blocking_issues() {
  local token="$1"
  local container_repo_id="$2"

  aikido_get "$token" "/api/public/v1/issues/export" \
    "format=json" \
    "filter_status=open" \
    "filter_container_repo_id=${container_repo_id}" \
    "filter_severities=critical,high" \
    "per_page=200" \
    | jq -c '
      (if type == "array" then . else (.issues // []) end)
      | map(select(((.severity // .risk // "") | ascii_downcase) as $s | $s == "critical" or $s == "high"))
    '
}

# Jedna linia logu na issue (CVE / pakiet / link do Aikido)
summarize_issue() {
  local issue_json="$1"
  printf '%s' "$issue_json" | jq -r --arg base "$AIKIDO_BASE" '
    (.severity // .risk // "") as $sev
    | ((.issue_group_id // .group_id // .issue_group.id // .id) | tostring) as $id
    | [
        (.cve_id // .cve // .aikido_id),
        (.package_name // .affected_package // .package),
        (.title // .name // .issue_title)
      ]
      | map(select(. != null and . != ""))
      | join(" | ") as $summary
    | "- [\(($sev | ascii_upcase))] \($summary // "Unknown issue")"
      + (if $id != "" and $id != "null" then " \($base)/issues/\($id)/detail?status=open" else "" end)
  '
}

# =============================================================================
# KROK 6 (main): orchestracja + decyzja PASS / FAIL
# =============================================================================
main() {
  local token match repos container_id issues count

  # Krok 3
  token="$(get_access_token)"
  echo "Checking Aikido for ${IMAGE_ARG}:${TAG_ARG}"
  echo "Match rules: name=${SHORT_NAME}${REGISTRY:+, registry=${REGISTRY}}, tag=${TAG_ARG}"

  # Krok 4
  if ! match="$(wait_for_scan "$token" "$TAG_ARG")"; then
    repos="$(list_repos "$token" || true)"
    if [[ -z "${repos:-}" || "${repos:-null}" == "[]" || "${repos:-null}" == "null" ]]; then
      echo "No Aikido container repository found for ${SHORT_NAME}${REGISTRY:+ (registry ${REGISTRY})}." >&2
      exit 1   # FAIL — brak repo
    fi
    echo "Timed out waiting for Aikido scan of ${IMAGE_ARG}:${TAG_ARG}." >&2
    printf '%s' "$repos" \
      | jq -r '[.[].last_scanned_tag | select(. != null and . != "")] | unique | join(", ")' \
      | { read -r tags || true; [[ -n "${tags:-}" ]] && echo "Seen last_scanned_tag values: ${tags}" >&2; }
    exit 1   # FAIL — brak skanu w czasie
  fi

  container_id="$(printf '%s' "$match" | jq -r '.id // .container_repo_id')"
  echo "Matched container ${container_id} ($(printf '%s' "$match" | jq -r '.registry_name // "unknown registry"'))"
  echo "Report: $(build_container_url "$container_id")"

  # Krok 5
  issues="$(get_blocking_issues "$token" "$container_id")"
  count="$(printf '%s' "$issues" | jq 'length')"

  # Krok 6 — decyzja
  if [[ "$count" -gt 0 ]]; then
    echo "Found ${count} open High/Critical vulnerabilities for ${IMAGE_ARG}:${TAG_ARG}:" >&2
    printf '%s' "$issues" | jq -c '.[:20][]' | while IFS= read -r issue; do
      summarize_issue "$issue" >&2
    done
    exit 1   # FAIL — są High/Critical
  fi

  echo "No open High/Critical vulnerabilities for ${IMAGE_ARG}:${TAG_ARG}."
  # PASS — exit 0 (domyślnie)
}

main
