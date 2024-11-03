#!/usr/bin/env bash

# Color definitions
NC='\033[0m'         # No Color - ${NC}
BRED='\033[1;31m'    # Red - ${BRED}
BGREEN='\033[1;32m'  # Green - ${BGREEN}
BYELLOW='\033[1;33m' # Yellow - ${BYELLOW}
BPURPLE='\033[1;35m' # Purple - ${BPURPLE}
BCYAN='\033[1;36m'   # Cyan - ${BCYAN}
BBLUE='\033[1;34m'   # Blue

# Define the path to wazuh-regex
WAZUH_REGEX_PATH="./wazuh-regex"
# If you have a local manual copy you need to define where the .so files are located
LD_LIBRARY_PATH=./wazuh-lib/:$LD_LIBRARY_PATH
# Path to the YAML file
YAML_FILE="./cis_ubuntu24-04.yml"
# Initialize pass, fail, and skip counters
total_count=0
pass_count=0
fail_count=0
skip_count=0
not_applicable_count=0
# Initialize an associative array to hold section counts
declare -A section_count

CIS_RULE_ID=""

LOG_PRINT_ACTUAL_OUTPUT=0
LOG_PRINT_DETAIL_CHECK=0
LOG_PRINT_SECTION_COUNT=0
SKIP_OS_CHECK=0

main() {
  if [[ "$SKIP_OS_CHECK" == 0 ]]; then
    # Validate each OS requirement
    echo -e "${BYELLOW}Validating OS requirements...${NC}"
    echo -e "${BYELLOW}#####################################################${NC}"
    # shellcheck disable=SC2155
    local requirements=$(yq '.requirements.rules' "$YAML_FILE")
    # shellcheck disable=SC2155
    local requirements_count=$(echo "$requirements" | jq 'length')

    for ((i = 0; i < requirements_count; i++)); do
      rule=$(echo "$requirements" | jq ".[${i}]")
      id="OS Requirement $((i + 1))"
      title="System Validation Requirement $((i + 1))"
      echo -e "\n${BYELLOW}💡 Check #${id}: ${title}${NC}"

      if run_check "$rule" "$id" "$title"; then
        echo -e "${BGREEN}✔ Check passed for #${id}: ${title}${NC}"
      else
        echo -e "${BRED}✖ Check failed for #${id}: ${title}${NC}"
      fi
    done
  fi

  # Check if a specific ID was provided as an argument
  if [[ -n "$CIS_RULE_ID" ]]; then
    echo -e "\n${BYELLOW}Running check for ID: ${CIS_RULE_ID}${NC}"
    echo -e "${BYELLOW}#####################################################${NC}"

    # Find the index of the specific check with the given ID
    # shellcheck disable=SC2155
    local index=$(echo "$all_checks" | jq "map(.id == $CIS_RULE_ID) | index(true)")

    if [[ -z "$index" || "$index" == "null" ]]; then
      echo -e "${BRED}\n🕵️ No rule found for ID: ${CIS_RULE_ID}${NC}"
      exit 1
    fi

    # Extract and run all rules for the specific check
    extract_from_yaml "$index"
  else
    echo -e "\n${BYELLOW}Starting all configuration checks...${NC}"
    echo -e "${BYELLOW}#####################################################${NC}"

    # Loop through each check in the YAML file
    # shellcheck disable=SC2155
    local check_count=$(echo "$all_checks" | jq 'length')
    for ((index = 0; index < check_count; index++)); do
      extract_from_yaml "$index"
    done
  fi

  # Print final results
  echo -e "\n${BYELLOW}All checks complete.${NC}"
  echo -e "${BCYAN}  ∞ Total Count          Checks: $total_count${NC}"
  echo -e "${BGREEN}  ✔ Total Passed         Checks: $pass_count${NC}"
  echo -e "${BGREEN}  ✔ Pass                  Score: $(awk "BEGIN {printf \"%.2f\", ($pass_count / ($total_count - $not_applicable_count)) * 100}")%${NC}"
  echo -e "${BRED}  ✖ Total Failed         Checks: $fail_count${NC}"
  echo -e "${BRED}  ✖ Fail                   Rate: $(awk "BEGIN {printf \"%.2f\", ($fail_count / ($total_count - $not_applicable_count)) * 100}")%${NC}"
  echo -e "${BPURPLE}  ↷ Total Not Applicable Checks: $not_applicable_count${NC}"
  echo -e "${BPURPLE}  ↷ Total Skipped        Checks: $skip_count${NC}"

  # Print the section counts
  if [[ $LOG_PRINT_SECTION_COUNT -eq 1 ]]; then
    echo -e "\n${BYELLOW}Rules per Section performed.${NC}"
    section_keys=("${!section_count[@]}")
    for ((index = ${#section_keys[@]} - 1; index >= 0; index--)); do
      section=${section_keys[index]}
      echo -e "${BCYAN} 📝 Section$section Count      : ${section_count[$section]}${NC}"
    done
  fi

}

# Function to parse and run a command, then check output against a regex
run_check() {
  local rule="$1"
  local id="$2"
  local title="$3"

  # Remove the leading and trailing double quotes
  rule=${rule#\"} # Removes the first double quote
  rule=${rule%\"} # Removes the last double quote

  # Split rule into command and regex parts using '->' as the delimiter
  local type_part_o="$rule" regex_part=""
  if [[ "$rule" == *" -> "* ]]; then
    type_part_o="${rule%% -> *}"
    regex_part="${rule#* -> }"
  fi

  # Negate if rule starts with "not"
  local negate=false
  local type_part="$type_part_o"
  if [[ "$type_part" == not* ]]; then
    type_part=${type_part#not } # Remove "not "
    negate=true
  fi

  # Define the command based on prefix
  local output
  case "$type_part" in
  f:*)
    if [[ ! -e "${type_part#f:}" ]]; then
      print_message not_applicable "$id" "$title" "$regex_part" "$type_part_o" "File does not exist!" # "$negate"
      return $?
    elif [[ -z "$regex_part" && -e "${type_part#f:}" ]]; then
      print_message success "$id" "$title" "$regex_part" "$type_part_o" "File does exist!" "$negate"
      return $?
    fi
    output=$(eval "cat ${type_part#f:}" 2>&1)
    ;;
  c:*)
    local command="${type_part#c:}"
    command="${command//\\\"/\"}" # Remove backslash before double quotes
    command="${command//\\\'/\'}" # Remove backslash before double quotes
    command="${command//\\\\/\\}" # Remove double backslashes
    output=$(eval "$command" 2>&1)
    # output=$(eval "sh -c \"$command\"" 2>&1)
    ;;
  p:*)
    # NOTE: not tested
    local process_name="${type_part#p:}"
    if pgrep -x "$process_name" >/dev/null; then
      print_message success "$id" "$title" "$regex_part" "$type_part_o" "Process running" "$negate"
    else
      print_message failed "$id" "$title" "$regex_part" "$type_part_o" "Process not found" "$negate"
    fi
    print_message error "$id" "$title" "$regex_part" "$type_part_o" "Process type is current not handled"
    return 2
    ;;
  d:*)
    local dir_path="${type_part#d:}"
    if [[ ! -d "$dir_path" ]]; then
      # print_message failed "$id" "$title" "$regex_part" "$type_part_o" "Directory not found" "$negate"
      print_message not_applicable "$id" "$title" "$regex_part" "$type_part_o" "Directory not found" "$negate"
      return $?
    fi

    if [[ -z "$regex_part" ]]; then
      print_message success "$id" "$title" "$regex_part" "$type_part_o" "Directory exists" "$negate"
      return $?
    else
      regex_part="${regex_part//\\\\/\\}"
      # Check if regex_part contains an additional '->' for nested checks
      if [[ "$regex_part" != *" -> "* ]]; then
        # Single regex: Find files matching pattern in directory
        local matching_files
        matching_files=$(find "$dir_path" -type f | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "${regex_part#r:}" 2>&1)
        if [[ -n "$matching_files" ]]; then
          print_message success "$id" "$title" "$regex_part" "$type_part_o" "Matching files found: $matching_files" "$negate"
          return $?
        else
          print_message failed "$id" "$title" "$regex_part" "$type_part_o" "No matching files found in directory" "$negate"
          return $?
        fi
      else
        # Nested regex: Find files matching first pattern, then check contents
        local file_regex_search="${regex_part%% -> *}"
        local file_content_regex_search="${regex_part#* -> }"
        matching_files=$(find "$dir_path" -type f | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "${file_regex_search#r:}" 2>&1)

        if [[ ${#matching_files[@]} -eq 0 ]]; then
          print_message failed "$id" "$title" "$regex_part" "$type_part_o" "No matching files found for pattern '$file_regex_search'" "$negate"
          return $?
        fi

        cleaned_files=$(echo "$matching_files" | awk '/^\+OSRegex_Execute:/ {print $2}' | sort -u 2>&1)
        if [[ -n "$cleaned_files" ]]; then
          IFS=$'\n' read -rd '' -a cleaned_files_array <<<"$cleaned_files"

          for file in "${cleaned_files_array[@]}"; do
            local file_output
            file_output=$(cat "$file" 2>&1)
            if process_file_check "$file_content_regex_search" "$file_output"; then
              print_message success "$id" "$title" "$file_content_regex_search" "$type_part_o" "File '$file' passed content checks" "$negate"
              return $?
            fi
          done

          # # Concatenate all files and check the complete content at once
          # local all_files_output
          # all_files_output=$(cat "${cleaned_files_array[@]}" 2>&1)
          # if process_file_check "$file_content_regex_search" "$all_files_output"; then
          #   print_message success "$id" "$title" "$file_content_regex_search" "$type_part_o" "Found searched content inside files" "$negate"
          #   return $?
          # fi
        fi

        print_message failed "$id" "$title" "$file_content_regex_search" "$type_part_o" "No files contains searched content" "$negate"
        return $?
      fi
    fi
    ;;
  *)
    print_message error "$id" "$title" "$regex_part" "$type_part_o" "Unknown command type in rule"
    return $?
    ;;
  esac

  process_file_check "$regex_part" "$output"
  process_file_check_status=$?
  if [[ $process_file_check_status == 0 ]]; then
    print_message success "$id" "$title" "$regex_part" "$type_part_o" "$output" "$negate"
    return $?
  elif [[ $process_file_check_status == 1 ]]; then
    print_message failed "$id" "$title" "$regex_part" "$type_part_o" "$output" "$negate"
    return $?
  fi
  return $process_file_check_status
}

process_file_check() {
  local regex_part="$1"
  local output="$2"
  local success="${3:0}"
  local output_result="$output"

  # Check if command execution not fall into not found
  if [[ -n "$output" && "$output" == *"command not found"* ]]; then
    # print_message error "$id" "$title" "$regex_part" "$type_part_o" "$output"
    print_message not_applicable "$id" "$title" "$regex_part" "$type_part_o" "$output" # "$negate"
    return $?
  fi

  # Handle regex patterns split by '&&'
  local regex_array
  IFS='&&' read -r -a regex_array <<<"$regex_part"

  # Process each regex pattern
  for regex in "${regex_array[@]}"; do
    [[ -z "$regex" ]] && continue              # Skip empty regex entries
    regex="${regex#"${regex%%[![:space:]]*}"}" # Remove leading whitespace
    regex="${regex%"${regex##*[![:space:]]}"}" # Remove trailing whitespace
    regex="${regex//\\\\/\\}"                  # Clean up any escaped backslashes

    # Count occurrences of each prefix type in the part
    count_r=$(grep -o "r:" <<<"$regex" | wc -l)
    count_n=$(grep -o "n:" <<<"$regex" | wc -l)
    count_not_r=$(grep -o "!r:" <<<"$regex" | wc -l)
    count_not_n=$(grep -o "!n:" <<<"$regex" | wc -l)
    if ((count_r > 1 || count_n > 1 || count_not_r > 1 || count_not_n > 1)); then
      print_message error "$id" "$title" "$regex_part" "$type_part_o" "Syntax error: Multiple occurrences of 'r:', 'n:', '!r:', or '!n:' in regex '$regex'"
      return $?
    fi

    success=0
    match_output=""
    compare=""
    verify=""

    case "$regex" in
    !r:*)
      regex="!${regex/#\!r:/}" # Remove 'r:' prefix
      ;;
    r:*)
      regex="${regex/#r:/}" # Remove 'r:' prefix
      ;;
    \!n:*)
      regex="!${regex/#\!n:/}" # Remove 'n:' prefix
      compare=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $1}')
      verify=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $2}')
      regex=$(echo "$regex" | awk -F ' compare ' '{print $1}')
      ;;
    n:*)
      regex="${regex/#n:/}" # Remove 'n:' prefix
      compare=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $1}')
      verify=$(echo "$regex" | awk -F ' compare ' '{print $2}' | awk '{print $2}')
      regex=$(echo "$regex" | awk -F ' compare ' '{print $1}')
      ;;
    *:*)
      print_message error "$id" "$title" "$regex_part" "$type_part_o" "Unknown pattern in 'Expected pattern'"
      return $?
      ;;
    *)
      print_message error "$id" "$title" "$regex_part" "$type_part_o" "Missing pattern in 'Expected pattern'"
      return $?
      ;;
    esac

    match_output=$(echo "$output_result" | LD_LIBRARY_PATH="$LD_LIBRARY_PATH" "$WAZUH_REGEX_PATH" "$regex" 2>&1)
    match_output=$(echo "$match_output" | sed -E 's/^\s*\+OS(Match_Compile|_Match2|Regex_Execute|_Regex)[[:space:]]*:[[:space:]]*//' | sort -u)

    if [[ -n "$match_output" ]]; then
      if [[ -n "$compare" && -n "$verify" ]]; then
        if [[ "$match_output" =~ \-Substring:\ (-?[0-9]+) ]]; then
          local captured_value="${BASH_REMATCH[1]}" # Extract captured number

          if compare_values "$captured_value" "$compare" "$verify"; then
            output_result=$match_output
            success=1
          else
            break
          fi
        fi
      else
        output_result=$match_output
        success=1
      fi
    else
      break
    fi
  done

  # Output results
  if [[ "$success" -eq 1 ]]; then
    return 0
  else
    return 1
  fi
}

extract_from_yaml() {
  local index="$1"
  local id cis_compliance title rules rules_count condition

  # Extract multiple fields at once for efficiency
  local check_data
  check_data=$(echo "$all_checks" | jq ".[$index] | {id, cis_compliance: (.compliance[] | select(.cis) | .cis[0]), title, rules, rules_count: (.rules | length), condition}")

  # Parse extracted data
  id=$(echo "$check_data" | jq -r '.id')
  cis_compliance=$(echo "$check_data" | jq -r '.cis_compliance')
  title="${cis_compliance} :: $(echo "$check_data" | jq -r '.title')"
  rules=$(echo "$check_data" | jq -r '.rules')
  rules_count=$(echo "$rules" | jq -r 'length')
  condition=$(echo "$check_data" | jq -r '.condition')

  # Print message if there are no rules defined
  if ((rules_count == 0)); then
    echo -e "${BPURPLE}\n👎 No rule checks defined for ID: #${id}, Title: ${title}${NC}"
    ((skip_count++))
    return
  fi

  [[ "$LOG_PRINT_DETAIL_CHECK" == 1 ]] && echo -e "\n${BYELLOW}💡 Check #${id}: ${title}${NC}"
  local rules_processed=0 rules_pass=0 rules_failed=0 rules_skipped=0 rules_not_applicable=0

  for ((j = 0; j < rules_count; j++)); do
    # shellcheck disable=SC2155
    local rule=$(echo "$rules" | jq ".[${j}]")
    run_check "$rule" "$id" "$title"
    case $? in
    0) ((rules_pass++)) ;;
    1) ((rules_failed++)) ;;
    2)
      ((rules_skipped++))
      ((rules_failed++))
      ;;
    3)
      ((rules_skipped++))
      ((rules_not_applicable++))
      ;;
    esac
    ((rules_processed++))
  done

  ((total_count++))
  [[ $LOG_PRINT_SECTION_COUNT -eq 1 ]] && ((section_count[${cis_compliance%%.*}]++))

  # if ((rules_skipped > 0)); then
  #   echo -e "${BPURPLE}↷ Check skipped for #${id}: ${title} (Condition: ${condition})${NC}"
  #   ((skip_count++))
  # fi
  # Process condition outcomes
  case "$condition" in
  "all")
    if ((rules_failed > 0)); then
      echo -e "${BRED}✖ Check failed for #${id}: ${title} (Condition: ${condition})${NC}"
      ((fail_count++))
    elif ((rules_failed == 0 && rules_processed == rules_pass)); then
      echo -e "${BGREEN}✔ Check passed for #${id}: ${title} (Condition: ${condition})${NC}"
      ((pass_count++))
    elif ((rules_not_applicable > 0)); then
      echo -e "${BPURPLE}↷ Check not applicable for #${id}: ${title} (Condition: ${condition})${NC}"
      ((not_applicable_count++))
    else
      echo -e "${BPURPLE}↷ Check skipped for #${id}: ${title} (Condition: ${condition})${NC}"
      ((skip_count++))
    fi
    ;;
  *)
    if ((rules_processed == rules_failed && rules_processed > 0)); then
      echo -e "${BRED}✖ Check failed for #${id}: ${title} (Condition: ${condition})${NC}"
      ((fail_count++))
    elif ((rules_processed > rules_failed && rules_processed > 0 && rules_pass > 0)); then
      echo -e "${BGREEN}✔ Check passed for #${id}: ${title} (Condition: ${condition})${NC}"
      ((pass_count++))
    elif ((rules_not_applicable > 0)); then
      echo -e "${BPURPLE}↷ Check not applicable for #${id}: ${title} (Condition: ${condition})${NC}"
      ((not_applicable_count++))
    else
      echo -e "${BPURPLE}↷ Check skipped for #${id}: ${title} (Condition: ${condition})${NC}"
      ((skip_count++))
    fi
    ;;
  esac
}

# Simplified comparison function
compare_values() {
  local value="$1"
  local operator="$2"
  local target="$3"

  case "$operator" in
  ">=") [[ "$value" -ge "$target" ]] ;;
  "<=") [[ "$value" -le "$target" ]] ;;
  ">") [[ "$value" -gt "$target" ]] ;;
  "<") [[ "$value" -lt "$target" ]] ;;
  "==") [[ "$value" -eq "$target" ]] ;;
  *) return 1 ;;
  esac
}

# Helper function to print messages
print_message() {
  local status="$1"
  local id="$2"
  local title="$3"
  local expected="$4"
  local command="$5"
  local output="$6"
  local negate="$7"

  if [[ "$negate" == true && "$status" == "success" ]]; then
    status="failed"
  elif [[ "$negate" == true && "$status" == "failed" ]]; then
    status="success"
  elif [[ "$negate" == true && "$status" == "not_applicable" ]]; then
    status="success"
  fi

  case "$status" in
  success)
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BGREEN}    ✔ Check passed for #${id}: ${title}${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Expected pattern: '${expected}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Command used    : '${command}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 && $LOG_PRINT_ACTUAL_OUTPUT -eq 1 ]] && echo -e "${BYELLOW}      - Actual output   : '${output}'${NC}"
    return 0
    ;;
  failed)
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BRED}    ✖ Check failed for #${id}: ${title}${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Expected pattern: '${expected}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Command used    : '${command}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 && $LOG_PRINT_ACTUAL_OUTPUT -eq 1 ]] && echo -e "${BYELLOW}      - Actual output   : '${output}'${NC}"
    return 1
    ;;
  not_applicable)
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BPURPLE}    ↷ Check not applicable for #${id}: ${title}${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Expected pattern: '${expected}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Command used    : '${command}'${NC}"
    [[ $LOG_PRINT_DETAIL_CHECK -eq 1 ]] && echo -e "${BYELLOW}      - Actual output   : '${output}'${NC}"
    return 3
    ;;
  error)
    echo -e "${BBLUE}   🍌 ERROR: for #${id}: ${title}${NC}"
    echo -e "${BBLUE}      - Expected pattern: '${expected}'${NC}"
    echo -e "${BBLUE}      - Command used    : '${command}'${NC}"
    echo -e "${BBLUE}      - Actual output   : '${output}'${NC}"
    return 2
    ;;
  esac
}

# Function to show usage information
usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -h,  --help                     Show this help message and exit"
  echo "  -i,  --id                       Define an ID to only check one specific rule"
  echo "  -f,  --file                     ..."
  echo "  -wr, --wazuh-regex              ..."
  echo "  -wl, --wazuh-libs               ..."
  echo "  -soc, --skip-os-check           ..."
  echo "  -pdc, --print-detail-check      ..."
  echo "  -pao, --print-actual-output     ..."
  echo "  -psc, --print-section-count     ..."
}

# Function to parse command-line arguments
parse_args() {
  while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    -h | --help)
      usage
      exit 0
      ;;
    -i | --id)
      CIS_RULE_ID="$2"
      shift
      ;;
    -f | --file)
      YAML_FILE="$2"
      shift
      ;;
    -wr | --wazuh-regex)
      WAZUH_REGEX_PATH="$2"
      shift
      ;;
    -wl | --wazuh-libs)
      LD_LIBRARY_PATH="$2:$LD_LIBRARY_PATH"
      shift
      ;;
    -soc | --skip-os-check)
      SKIP_OS_CHECK=1
      ;;
    -pdc | --print-detail-check)
      LOG_PRINT_DETAIL_CHECK=1
      ;;
    -pao | --print-actual-output)
      LOG_PRINT_ACTUAL_OUTPUT=1
      ;;
    -psc | --print-section-count)
      LOG_PRINT_SECTION_COUNT=1
      ;;
    *)
      echo "Unknown option: $key" >&2
      usage
      exit 1
      ;;
    esac
    shift
  done
}

echo "Starting script $0 ..."

# Parse command-line arguments
parse_args "$@"

# Check if YAML_FILE exists
if [[ ! -f "$YAML_FILE" ]]; then
  echo -e "${BRED}YAML file not found at ${YAML_FILE}. Please verify the file path.${NC}"
  exit 1
fi

# Ensure yq is installed and executable
if ! command -v yq &>/dev/null; then
  echo -e "${BRED}yq could not be found. Please install it to parse YAML files.${NC}"
  echo -e "${BYELLOW}Install with 'sudo apt install yq'${NC}"
  exit 1
fi

# Ensure jq is installed and executable
if ! command -v jq &>/dev/null; then
  echo -e "${BRED}jq could not be found. Please install it to parse JSON files.${NC}"
  echo -e "${BYELLOW}Install with 'sudo apt install jq'${NC}"
  exit 1
fi

# Ensure wazuh-regex is installed and executable
if ! command -v "$WAZUH_REGEX_PATH" &>/dev/null; then
  echo -e "${BRED}wazuh-regex could not be found at ${WAZUH_REGEX_PATH}. Please ensure it is accessible or update WAZUH_REGEX_PATH.${NC}"
  echo -e "${BYELLOW}Example install manually as follow:${NC}"
  echo -e "${BYELLOW}  - 'wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/wazuh-manager_4.9.1-1_amd64.deb'${NC}"
  echo -e "${BYELLOW}  - 'mkdir wazuh-manager && dpkg-deb -R wazuh-manager_4.9.1-1_amd64.deb wazuh-manager'${NC}"
  echo -e "${BYELLOW}  - 'cp ./wazuh-manager/var/ossec/bin/wazuh-regex .'${NC}"
  echo -e "${BYELLOW}  - 'mkdir wazuh-lib && cp -r ./wazuh-manager/var/ossec/lib/* ./wazuh-lib'${NC}"
  echo -e "${BYELLOW}  - 'rm wazuh-manager* -rf'${NC}"
  echo -e "${BYELLOW}  - 'chmod u+x wazuh-regex'${NC}"

  exit 1
fi

# Load all checks data once
all_checks=$(yq '.checks' "$YAML_FILE")

main
exit 0
