#!/usr/bin/env bash
# shellcheck shell=bash

# =============================================================================
# SCA Rule Testing Script for Wazuh
# Tests SCA policies (YAML) locally using wazuh-regex
# =============================================================================

set -uo pipefail

# -----------------------------------------------------------------------------
# Color definitions
# -----------------------------------------------------------------------------
NC='\033[0m'         # No Color
BRED='\033[1;31m'    # Red
BGREEN='\033[1;32m'  # Green
BYELLOW='\033[1;33m' # Yellow
BPURPLE='\033[1;35m' # Purple
BCYAN='\033[1;36m'   # Cyan

# -----------------------------------------------------------------------------
# Default configuration
# -----------------------------------------------------------------------------
WAZUH_REGEX_PATH="${WAZUH_REGEX_PATH:-./wazuh-regex}"
# If you have a local manual copy you need to define where the .so files are located
LD_LIBRARY_PATH="./wazuh-lib:${LD_LIBRARY_PATH:-}"
YAML_FILE="${YAML_FILE:-./cis_ubuntu24-04-v2024.yml}"

# Counters
total_count=0
pass_count=0
fail_count=0
skip_count=0
not_applicable_count=0
declare -A section_count=()
declare -A cis_compliance_by_id=()

# Runtime options
CIS_RULE_ID=""
LOG_PRINT_ACTUAL_OUTPUT=0
LOG_PRINT_DETAIL_CHECK=0
LOG_PRINT_SECTION_COUNT=0
SKIP_OS_CHECK=0

# Global data
all_checks=""

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

log_info() { echo -e "${BCYAN}${*}${NC}"; }
log_success() { echo -e "${BGREEN}${*}${NC}"; }
log_warning() { echo -e "${BYELLOW}${*}${NC}"; }
log_error() { echo -e "${BRED}${*}${NC}"; }
log_debug() { [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BPURPLE}${*}${NC}"; }

# Safe command execution without eval
run_command() {
  local cmd="$1"
  # Use bash -c for proper parsing without eval
  bash -c "$cmd" 2>&1
}

# Strip wazuh-regex output prefixes (e.g. "+OSRegex_Execute:") from lines
# and optionally sort unique (used in process_regex / process_comparison /
# nested d: file matching)
strip_match_output() {
  local input="$1"
  local sort_unique="${2:-false}"

  local result
  result=$(echo "$input" | sed -E 's/^\s*\+OS(Match_Compile|_Match2|Regex_Execute|_Regex)[[:space:]]*:[[:space:]]*//')
  if [[ "$sort_unique" == "true" ]]; then
    result=$(echo "$result" | sort -u)
  fi

  echo "$result"
}

# -----------------------------------------------------------------------------
# Core Check Functions
# -----------------------------------------------------------------------------

# Process a regex pattern against output
# Returns: 0=match, 1=no match, 2=error, 3=not applicable
process_regex() {
  local regex="$1"
  local output="$2"
  local negate="${3:-false}"

  local match_output rc
  match_output=$(echo "$output" | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "$regex" 2>&1)
  rc=$?
  # wazuh-regex exits 255 when the regex does not compile; bail as an error
  # rather than letting the error text count as a match (false pass).
  if [[ $rc -eq 255 ]]; then
    return 2
  fi
  match_output=$(strip_match_output "$match_output" "true")

  local matched=0
  if [[ -n "$match_output" ]]; then
    matched=1
  fi

  # Apply negation
  if [[ "$negate" == "true" ]]; then
    matched=$((1 - matched))
  fi

  if [[ $matched -eq 1 ]]; then
    return 0
  else
    return 1
  fi
}

# Process comparison (n: / !n:)
process_comparison() {
  local regex="$1"
  local output="$2"
  local negate="${3:-false}"

  # Extract compare operator and value
  # Format: "pattern compare OP VALUE"
  local compare_op compare_val pattern
  pattern=$(echo "$regex" | awk -F ' compare ' '{print $1}')
  compare_op=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $1}')
  compare_val=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $2}')

  if [[ -z "$compare_op" || -z "$compare_val" ]]; then
    return 2
  fi

  # Guard against non-numeric comparison values (policy drift)
  if [[ ! "$compare_val" =~ ^-?[0-9]+$ ]]; then
    return 2
  fi

  local match_output rc
  match_output=$(echo "$output" | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "$pattern" 2>&1)
  rc=$?
  if [[ $rc -eq 255 ]]; then
    return 2
  fi
  match_output=$(strip_match_output "$match_output")

  if [[ -z "$match_output" ]]; then
    return 1
  fi

  # Extract captured number from -Substring: (allow leading non-numeric text, e.g. "enabled=0")
  local captured_value
  if [[ "$match_output" =~ -Substring:[[:space:]]*[^0-9-]*(-?[0-9]+) ]]; then
    captured_value="${BASH_REMATCH[1]}"
  else
    return 1
  fi

  local result=0
  case "$compare_op" in
    ">=") [[ "$captured_value" -ge "$compare_val" ]] || result=1 ;;
    "<=") [[ "$captured_value" -le "$compare_val" ]] || result=1 ;;
    ">")  [[ "$captured_value" -gt "$compare_val" ]] || result=1 ;;
    "<")  [[ "$captured_value" -lt "$compare_val" ]] || result=1 ;;
    "==") [[ "$captured_value" -eq "$compare_val" ]] || result=1 ;;
    "!=") [[ "$captured_value" -ne "$compare_val" ]] || result=1 ;;
    *) return 2 ;;
  esac

  if [[ "$negate" == "true" ]]; then
    result=$((1 - result))
  fi

  return $result
}

# Process a single regex part (handles r:, !r:, n:, !n:)
process_regex_part() {
  local regex_part="$1"
  local output="$2"
  local id="$3"
  local title="$4"
  local command="$5"
  local expected="$6"

  # Skip empty
  [[ -z "$regex_part" ]] && return 0

  # Trim whitespace
  regex_part="${regex_part#"${regex_part%%[![:space:]]*}"}"
  regex_part="${regex_part%"${regex_part##*[![:space:]]}"}"

  # Validate single occurrence of each prefix
  local count_r count_n count_not_r count_not_n
  count_r=$(grep -o "r:" <<<"$regex_part" | wc -l)
  count_n=$(grep -o "n:" <<<"$regex_part" | wc -l)
  count_not_r=$(grep -o "!r:" <<<"$regex_part" | wc -l)
  count_not_n=$(grep -o "!n:" <<<"$regex_part" | wc -l)
  if ((count_r > 1 || count_n > 1 || count_not_r > 1 || count_not_n > 1)); then
    print_message "error" "$id" "$title" "$expected" "$command" "Syntax error: Multiple prefixes in '$regex_part'"
    return 2
  fi

  case "$regex_part" in
    !r:*)
      process_regex "${regex_part#!r:}" "$output" "true"
      return $?
      ;;
    r:*)
      process_regex "${regex_part#r:}" "$output" "false"
      return $?
      ;;
    !n:*)
      process_comparison "${regex_part#!n:}" "$output" "true"
      return $?
      ;;
    n:*)
      process_comparison "${regex_part#n:}" "$output" "false"
      return $?
      ;;
    *:*)
      # Unknown prefixes (e.g. "conds:" or a typo) are silently treated
      # as plain regexes by Wazuh; keep that behaviour for regexes that
      # merely contain a colon, but flag word-like prefixes as errors.
      local prefix="${regex_part%%:*}"
      if [[ "$prefix" =~ ^[[:alpha:]][[:alnum:]]*$ ]]; then
        print_message "error" "$id" "$title" "$expected" "$command" "Unknown regex prefix in '$regex_part'"
        return 2
      fi
      process_regex "$regex_part" "$output" "false"
      return $?
      ;;
    *)
      # Prefix-less regex (e.g. "f:/path -> regex"): treat as r:
      process_regex "$regex_part" "$output" "false"
      return $?
      ;;
  esac
}

# Process file check with && logic
process_file_check() {
  local regex_part="$1"
  local output="$2"
  local id="$3"
  local title="$4"
  local command="$5"
  local expected="$6"

  # Check for command not found
  if [[ -n "$output" && "$output" == *"command not found"* ]]; then
    print_message "not_applicable" "$id" "$title" "$expected" "$command" "$output"
    return 3
  fi

  # Split by &&
  local regex_array
  IFS='&&' read -r -a regex_array <<<"$regex_part"

  for regex in "${regex_array[@]}"; do
    process_regex_part "$regex" "$output" "$id" "$title" "$command" "$expected"
    local result=$?
    if [[ $result -ne 0 ]]; then
      return $result
    fi
  done

  return 0
}

# Print formatted message and return appropriate exit code
print_message() {
  local status="$1"
  local id="$2"
  local title="$3"
  local expected="$4"
  local command="$5"
  local output="$6"
  local negate="${7:-false}"

  # Apply negation to status
  if [[ "$negate" == "true" ]]; then
    case "$status" in
      success) status="failed" ;;
      failed) status="success" ;;
      not_applicable) status="success" ;;
    esac
  fi

  case "$status" in
    success)
      log_debug "    ✔ Check passed for #${id}: ${title}"
      log_debug "      - Expected pattern: '${expected}'"
      log_debug "      - Command used    : '${command}'"
      [[ $LOG_PRINT_ACTUAL_OUTPUT -eq 1 ]] && log_debug "      - Actual output   : '${output}'"
      return 0
      ;;
    failed)
      log_debug "    ✖ Check failed for #${id}: ${title}"
      log_debug "      - Expected pattern: '${expected}'"
      log_debug "      - Command used    : '${command}'"
      [[ $LOG_PRINT_ACTUAL_OUTPUT -eq 1 ]] && log_debug "      - Actual output   : '${output}'"
      return 1
      ;;
    not_applicable)
      log_debug "    ↷ Check not applicable for #${id}: ${title}"
      log_debug "      - Expected pattern: '${expected}'"
      log_debug "      - Command used    : '${command}'"
      log_debug "      - Actual output   : '${output}'"
      return 3
      ;;
    error)
      log_error "   🍌 ERROR for #${id}: ${title}"
      log_error "      - Expected pattern: '${expected}'"
      log_error "      - Command used    : '${command}'"
      log_error "      - Actual output   : '${output}'"
      return 2
      ;;
    *)
      log_error "   💥 Unknown status for #${id}: ${title}"
      return 2
      ;;
  esac
}

# -----------------------------------------------------------------------------
# Rule Execution
# -----------------------------------------------------------------------------

run_check() {
  local rule="$1"
  local id="$2"
  local title="$3"

  # Split rule into command and regex parts
  # type_part_o = original value before any "not " negation is stripped
  local type_part_o="$rule" regex_part=""
  if [[ "$rule" == *" -> "* ]]; then
    type_part_o="${rule%% -> *}"
    regex_part="${rule#* -> }"
  fi

  # Handle negation
  local negate=false
  local type_part="$type_part_o"
  if [[ "$type_part" == "not "* ]]; then
    type_part="${type_part#not }"
    negate=true
  fi

  local output
  case "$type_part" in
    f:*)
      local file_path="${type_part#f:}"
      if [[ ! -e "$file_path" ]]; then
        print_message "not_applicable" "$id" "$title" "$regex_part" "$type_part_o" "File does not exist: $file_path" "$negate"
        return $?
      elif [[ -z "$regex_part" ]]; then
        print_message "success" "$id" "$title" "$regex_part" "$type_part_o" "File exists: $file_path" "$negate"
        return $?
      fi
      output=$(cat "$file_path" 2>&1)
      ;;
    c:*)
      local command="${type_part#c:}"
      output=$(run_command "$command")
      ;;
    p:*)
      # NOTE: not exercised by bundled policies
      local process_name="${type_part#p:}"
      if pgrep -x "$process_name" >/dev/null; then
        print_message "success" "$id" "$title" "$regex_part" "$type_part_o" "Process running: $process_name" "$negate"
      else
        print_message "failed" "$id" "$title" "$regex_part" "$type_part_o" "Process not found: $process_name" "$negate"
      fi
      return $?
      ;;
    d:*)
      local dir_path="${type_part#d:}"
      if [[ ! -d "$dir_path" ]]; then
        print_message "not_applicable" "$id" "$title" "$regex_part" "$type_part_o" "Directory not found: $dir_path" "$negate"
        return $?
      fi
      if [[ -z "$regex_part" ]]; then
        print_message "success" "$id" "$title" "$regex_part" "$type_part_o" "Directory exists: $dir_path" "$negate"
        return $?
      fi
      # Directory with regex - find files matching pattern, then check contents
      regex_part="${regex_part//\\\\/\\}"
      if [[ "$regex_part" != *" -> "* ]]; then
        # Single regex: find files matching pattern
        local matching_files
        matching_files=$(find "$dir_path" -type f 2>/dev/null | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "${regex_part#r:}" 2>&1)
        if [[ -n "$matching_files" ]]; then
          print_message "success" "$id" "$title" "$regex_part" "$type_part_o" "Matching files found: $matching_files" "$negate"
          return $?
        else
          print_message "failed" "$id" "$title" "$regex_part" "$type_part_o" "No matching files found in directory" "$negate"
          return $?
        fi
      else
        # Nested: file regex -> content regex
        local file_regex="${regex_part%% -> *}"
        local content_regex="${regex_part#* -> }"
        local matching_files
        matching_files=$(find "$dir_path" -type f 2>/dev/null | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "${file_regex#r:}" 2>&1)
        matching_files=$(strip_match_output "$matching_files" "true")
        if [[ -z "$matching_files" ]]; then
          print_message "failed" "$id" "$title" "$file_regex" "$type_part_o" "No matching files found for pattern '$file_regex'" "$negate"
          return $?
        fi
        local found=0
        while IFS= read -r file; do
          [[ -z "$file" ]] && continue
          local file_output
          file_output=$(cat "$file" 2>&1)
          if process_file_check "$content_regex" "$file_output" "$id" "$title" "cat $file" "$content_regex"; then
            found=1
            break
          fi
        done <<<"$matching_files"
        if [[ $found -eq 1 ]]; then
          print_message "success" "$id" "$title" "$content_regex" "$type_part_o" "Found searched content in matching files" "$negate"
          return 0
        else
          print_message "failed" "$id" "$title" "$content_regex" "$type_part_o" "No files contain searched content" "$negate"
          return 1
        fi
      fi
      ;;
    *)
      print_message "error" "$id" "$title" "$regex_part" "$type_part_o" "Unknown command type: $type_part"
      return 2
      ;;
  esac

  # Process the regex against output
  process_file_check "$regex_part" "$output" "$id" "$title" "$type_part_o" "$regex_part"
  local result=$?

  # Print per-rule detail for regex/compare rules (the -pdc / -pao path)
  if [[ $LOG_PRINT_ACTUAL_OUTPUT -eq 1 && $result -ne 2 ]]; then
    log_debug "      - Expected pattern: '${regex_part}'"
    log_debug "      - Actual output   : '${output}'"
  fi

  # Apply negation for final result
  if [[ "$negate" == "true" ]]; then
    case $result in
      0) return 1 ;;
      1) return 0 ;;
      3) return 0 ;;
      *) return $result ;;
    esac
  fi

  return $result
}

# -----------------------------------------------------------------------------
# YAML Extraction
# -----------------------------------------------------------------------------

# Wazuh changed its policy format: the per-check `cis` compliance mapping
# (e.g. compliance -> [cis: "1.1.1.1"]) was removed. New policies only carry
# the CIS reference in a comment above each check (`# 1.1.1.1 Ensure ...`).
# When several CIS rules are grouped into one check they are listed as
# sequential comments ending on the rule the check actually implements
# (verified against the old `compliance.cis[0]` mapping). Build an
# id -> cis-reference map from the trailing comment of each group so section
# reports (-psc) and the "CIS x.y.z :: title" prefix keep working for both
# formats.
build_cis_compliance_map() {
  cis_compliance_by_id=()
  local pending=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*([0-9]+(\.[0-9]+)+)[[:space:]] ]]; then
      pending="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[[:space:]]*-[[:space:]]*id:[[:space:]]*([0-9]+) ]]; then
      if [[ -n "$pending" ]]; then
        cis_compliance_by_id["${BASH_REMATCH[1]}"]="$pending"
      fi
      pending=""
    fi
  done < "$YAML_FILE"
}

extract_from_yaml() {
  local index="$1"
  local id cis_compliance title rules rules_count condition

  # Extract check data
  local check_data
  check_data=$(echo "$all_checks" | jq --arg idx "$index" '.[$idx | tonumber] | {
    id,
    title: (.name // .title),
    rules,
    rules_count: (.rules | length),
    condition
  }')

  id=$(echo "$check_data" | jq -r '.id // empty')
  cis_compliance="${cis_compliance_by_id[$id]:-unknown}"
  title="${cis_compliance} :: $(echo "$check_data" | jq -r '.title // empty')"
  rules=$(echo "$check_data" | jq -r '.rules')
  rules_count=$(echo "$check_data" | jq -r '.rules_count // 0')
  condition=$(echo "$check_data" | jq -r '.condition // "all"')

  if ((rules_count == 0)); then
    log_warning "\n👎 No rule checks defined for ID: #${id}, Title: ${title}"
    ((skip_count++))
    return
  fi

  [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && log_warning "\n💡 Check #${id}: ${title}"

  local rules_processed=0 rules_pass=0 rules_failed=0 rules_not_applicable=0 rules_error=0

  for ((j = 0; j < rules_count; j++)); do
    local rule
    rule=$(echo "$rules" | jq -r ".[${j}]")
    run_check "$rule" "$id" "$title"
    case $? in
      0) ((rules_pass++)) ;;
      1) ((rules_failed++)) ;;
      2)
        ((rules_failed++))
        ((rules_error++))
        ;;
      3)
        ((rules_not_applicable++))
        ;;
    esac
    ((rules_processed++))
  done

  ((total_count++))
  [[ $LOG_PRINT_SECTION_COUNT -eq 1 ]] && ((section_count["${cis_compliance%%.*}"]++))

  # Evaluate condition
  case "$condition" in
    "all")
      if ((rules_failed > 0)); then
        log_error "✖ Check failed for #${id}: ${title} (Condition: ${condition})"
        ((fail_count++))
      elif ((rules_processed == rules_pass)); then
        log_success "✔ Check passed for #${id}: ${title} (Condition: ${condition})"
        ((pass_count++))
      elif ((rules_not_applicable > 0)); then
        log_warning "↷ Check not applicable for #${id}: ${title} (Condition: ${condition})"
        ((not_applicable_count++))
      else
        log_warning "↷ Check skipped for #${id}: ${title} (Condition: ${condition})"
        ((skip_count++))
      fi
      ;;
    "any"|"one")
      if ((rules_pass > 0)); then
        log_success "✔ Check passed for #${id}: ${title} (Condition: ${condition})"
        ((pass_count++))
      elif ((rules_not_applicable > 0 && rules_processed == rules_not_applicable)); then
        log_warning "↷ Check not applicable for #${id}: ${title} (Condition: ${condition})"
        ((not_applicable_count++))
      else
        log_error "✖ Check failed for #${id}: ${title} (Condition: ${condition})"
        ((fail_count++))
      fi
      ;;
    "none")
      # Pass only if no rule matched and no rule errored
      if ((rules_error > 0 || rules_pass > 0)); then
        log_error "✖ Check failed for #${id}: ${title} (Condition: ${condition})"
        ((fail_count++))
      elif ((rules_not_applicable > 0 && rules_processed == rules_not_applicable)); then
        log_warning "↷ Check not applicable for #${id}: ${title} (Condition: ${condition})"
        ((not_applicable_count++))
      else
        log_success "✔ Check passed for #${id}: ${title} (Condition: ${condition})"
        ((pass_count++))
      fi
      ;;
    *)
      # Default to 'all' behavior for unknown conditions
      if ((rules_failed > 0)); then
        log_error "✖ Check failed for #${id}: ${title} (Condition: ${condition})"
        ((fail_count++))
      elif ((rules_processed > rules_failed && rules_pass > 0)); then
        log_success "✔ Check passed for #${id}: ${title} (Condition: ${condition})"
        ((pass_count++))
      elif ((rules_not_applicable > 0)); then
        log_warning "↷ Check not applicable for #${id}: ${title} (Condition: ${condition})"
        ((not_applicable_count++))
      else
        log_warning "↷ Check skipped for #${id}: ${title} (Condition: ${condition})"
        ((skip_count++))
      fi
      ;;
  esac
}

# -----------------------------------------------------------------------------
# OS Requirements Check
# -----------------------------------------------------------------------------

check_os_requirements() {
  [[ $SKIP_OS_CHECK -eq 1 ]] && return 0

  log_info "Validating OS requirements..."
  log_info "#####################################################"

  local requirements requirements_count
  requirements=$(yq -o=json '.requirements.rules' "$YAML_FILE" 2>/dev/null || yq '.requirements.rules' "$YAML_FILE" 2>/dev/null || echo "[]")
  requirements_count=$(echo "$requirements" | jq 'length')

  for ((i = 0; i < requirements_count; i++)); do
    local rule id title
    rule=$(echo "$requirements" | jq -r ".[${i}]")
    id="OS Requirement $((i + 1))"
    title="System Validation Requirement $((i + 1))"
    log_warning "\n💡 Check #${id}: ${title}"

    if run_check "$rule" "$id" "$title"; then
      log_success "✔ Check passed for #${id}: ${title}"
    else
      log_error "✖ Check failed for #${id}: ${title}"
    fi
  done
}

# -----------------------------------------------------------------------------
# Main Functions
# -----------------------------------------------------------------------------

run_specific_check() {
  log_warning "\nRunning check for ID: ${CIS_RULE_ID}"
  log_warning "#####################################################"

  local index
  index=$(echo "$all_checks" | jq --arg id "$CIS_RULE_ID" 'map((.id | tostring) == $id) | index(true)')

  if [[ -z "$index" || "$index" == "null" ]]; then
    log_error "\n🕵️ No rule found for ID: ${CIS_RULE_ID}"
    exit 1
  fi

  extract_from_yaml "$index"
}

run_all_checks() {
  log_warning "\nStarting all configuration checks..."
  log_warning "#####################################################"

  local check_count
  check_count=$(echo "$all_checks" | jq 'length')

  for ((index = 0; index < check_count; index++)); do
    extract_from_yaml "$index"
  done
}

print_summary() {
  log_info "\nAll checks complete."
  log_info "  ∞ Total Count          Checks: $total_count"
  log_success "  ✔ Total Passed         Checks: $pass_count"
  local pass_rate=0
  if ((total_count - not_applicable_count > 0)); then
    pass_rate=$(awk -v p="$pass_count" -v t="$((total_count - not_applicable_count))" 'BEGIN {printf "%.2f", (p / t) * 100}')
  fi
  log_success "  ✔ Pass                  Score: ${pass_rate}%"
  log_error "  ✖ Total Failed         Checks: $fail_count"
  local fail_rate=0
  if ((total_count - not_applicable_count > 0)); then
    fail_rate=$(awk -v p="$fail_count" -v t="$((total_count - not_applicable_count))" 'BEGIN {printf "%.2f", (p / t) * 100}')
  fi
  log_error "  ✖ Fail                   Rate: ${fail_rate}%"
  log_warning "  ↷ Total Not Applicable Checks: $not_applicable_count"
  log_warning "  ↷ Total Skipped        Checks: $skip_count"

  if [[ $LOG_PRINT_SECTION_COUNT -eq 1 ]]; then
    log_warning "\nRules per Section performed."
    local section_keys=("${!section_count[@]}")
    for ((index = ${#section_keys[@]} - 1; index >= 0; index--)); do
      local section="${section_keys[index]}"
      log_info " 📝 Section ${section} Count: ${section_count[$section]}"
    done
  fi
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -h, --help                     Show this help message and exit
  -i, --id <ID>                  Run only the check with the specified ID
  -f, --file <FILE>              Path to the SCA YAML file (default: ./cis_ubuntu24-04-v2024.yml)
  -wr, --wazuh-regex <PATH>      Path to wazuh-regex binary (default: ./wazuh-regex)
  -wl, --wazuh-libs <PATH>       Path to wazuh lib directory (default: ./wazuh-lib)
  -soc, --skip-os-check          Skip OS requirement validation
  -pdc, --print-detail-check     Print detailed check output
  -pao, --print-actual-output    Print actual command output (requires -pdc)
  -psc, --print-section-count    Print rule count per section

Examples:
  # Run all checks with detail
  $0 -pdc

  # Run specific rule ID
  $0 -soc -pdc -i 18500

  # Use custom YAML file
  $0 -f ./cis_ubuntu22-04.yml -pdc

  # Run with custom wazuh-regex path
  $0 -wr /usr/bin/wazuh-regex -wl /var/ossec/lib
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        usage
        exit 0
        ;;
      -i|--id)
        CIS_RULE_ID="$2"
        shift 2
        ;;
      -f|--file)
        YAML_FILE="$2"
        shift 2
        ;;
      -wr|--wazuh-regex)
        WAZUH_REGEX_PATH="$2"
        shift 2
        ;;
      -wl|--wazuh-libs)
        LD_LIBRARY_PATH="$2:${LD_LIBRARY_PATH}"
        shift 2
        ;;
      -soc|--skip-os-check)
        SKIP_OS_CHECK=1
        shift
        ;;
      -pdc|--print-detail-check)
        LOG_PRINT_DETAIL_CHECK=1
        shift
        ;;
      -pao|--print-actual-output)
        LOG_PRINT_ACTUAL_OUTPUT=1
        shift
        ;;
      -psc|--print-section-count)
        LOG_PRINT_SECTION_COUNT=1
        shift
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# Dependency Checks
# -----------------------------------------------------------------------------

check_dependencies() {
  # Check YAML file
  if [[ ! -f "$YAML_FILE" ]]; then
    log_error "YAML file not found at ${YAML_FILE}. Please verify the file path."
    exit 1
  fi

  # Check yq
  if ! command -v yq &>/dev/null; then
    log_error "yq could not be found. Please install it to parse YAML files."
    log_warning "Install with: sudo apt install yq"
    exit 1
  fi

  # Check jq
  if ! command -v jq &>/dev/null; then
    log_error "jq could not be found. Please install it to parse JSON files."
    log_warning "Install with: sudo apt install jq"
    exit 1
  fi

  # Check wazuh-regex
  if [[ ! -x "$WAZUH_REGEX_PATH" ]]; then
    log_error "wazuh-regex not found or not executable at ${WAZUH_REGEX_PATH}"
    log_warning "Install with: ./install-wazuh-regex.sh  (no root needed)"
    log_warning "Optionally pin another version: WAZUH_MANAGER_VERSION=4.9.1-1 ./install-wazuh-regex.sh"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

main() {
  log_info "Starting SCA rule testing..."

  parse_args "$@"
  check_dependencies

  # Load all checks data (works with both kislyuk/yq (apt, JSON output) and mikefarah/yq (-o=json))
  all_checks=$(yq -o=json '.checks' "$YAML_FILE" 2>/dev/null || yq '.checks' "$YAML_FILE")
  if [[ -z "$all_checks" || "$all_checks" == "null" ]]; then
    log_error "No checks found in YAML file"
    exit 1
  fi

  build_cis_compliance_map

  check_os_requirements

  if [[ -n "$CIS_RULE_ID" ]]; then
    run_specific_check
  else
    run_all_checks
  fi

  print_summary

  # Exit with error code if any checks failed
  if ((fail_count > 0)); then
    exit 1
  fi
}

main "$@"
