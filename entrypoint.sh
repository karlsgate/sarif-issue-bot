#!/bin/bash

set -e

# Function to log error messages and exit
log_error_and_exit() {
  echo "Error: $1"
  exit 1
}

# Validate required inputs
[ -z "$1" ] && log_error_and_exit "Token input is required"
[ -z "$2" ] && log_error_and_exit "SARIF file input is required"
[ -z "$3" ] && log_error_and_exit "Image name input is required"

INPUT_GITHUB_TOKEN="$1"
INPUT_SARIF_FILE="$2"
INPUT_IMAGE_NAME="$3"
INPUT_PROJECT="$4"
INPUT_ALLOW_REOPENING="${5:-true}"
INPUT_ALLOW_CLOSING="${6:-true}"

# Configure Git to trust the workspace directory
git config --global --add safe.directory /github/workspace

# Authenticate with GitHub CLI
echo "$INPUT_GITHUB_TOKEN" | gh auth login --with-token

# Function to generate a random color
generate_random_color() {
  printf '%06X\n' $((RANDOM % 16777215))
}

# Function to create a label if it doesn't exist
create_label_if_not_exists() {
  local label=$1
  local color=$2
  local description=$3
  
  if ! gh label list | grep -q "$label"; then
    gh label create "$label" --color "$color" --description "$description" || echo "Failed to create label: $label"
  fi
}

# Create necessary labels
create_label_if_not_exists "vulnerability" "d73a4a" "Security vulnerability"
create_label_if_not_exists "critical" "b60205" "Critical severity"
create_label_if_not_exists "high" "d93f0b" "High severity"
create_label_if_not_exists "medium" "fbca04" "Medium severity"
create_label_if_not_exists "low" "0e8a16" "Low severity"

if [ -n "$INPUT_PROJECT" ]; then
  random_color=$(generate_random_color)
  create_label_if_not_exists "$INPUT_PROJECT" "$random_color" "Project: $INPUT_IMAGE_NAME"
fi

# Read vulnerabilities from SARIF file
vulnerabilities=$(jq -r '.runs[0].tool.driver.rules[] | {
  title: "[TESTING] - Vulnerability (\(.properties.cvssV3_severity)): \(.id) @ '"$INPUT_IMAGE_NAME"'",
  severity: .properties.cvssV3_severity,
  name: .name,
  description: .help.text,
  affected_version: .properties.affected_version,
  fixed_version: .properties.fixed_version,
  security_severity: .properties."security-severity",
  help_uri: .helpUri,
  purls: .properties.purls
}' "$INPUT_SARIF_FILE")

# Fetch all issues with the 'vulnerability' label
existing_issues=$(gh issue list --label vulnerability --json number,title,state,labels)

# Function to create a new issue
ccreate_issue() {
  local title="$1"
  local body="$2"
  local labels="$3"

  gh issue create --title "$title" --body "$body" --label "$labels"
  echo "Created issue: $title with labels: $labels"
}

# Function to update an existing issue
update_issue() {
  local issue_number="$1"
  local title="$2"
  local body="$3"
  local labels="$4"
  local issue_state="$5"
  local current_labels="$6"

  if [ "$issue_state" = "closed" ] && [ "$INPUT_ALLOW_REOPENING" = "true" ]; then
    gh issue reopen "$issue_number" --comment "This issue has been reopened because it is present in the latest scan."
    echo "Reopened issue: $title"
  fi

  # Update labels
  IFS=',' read -ra label_array <<< "$labels"
  for label in "${label_array[@]}"; do
    if [[ ! "$current_labels" == *"$label"* ]]; then
      gh issue edit "$issue_number" --add-label "$label"
    fi
  done

  echo "Updated issue #$issue_number: $title with labels: $labels"
}

# Create an array to store current vulnerability titles
current_vulnerabilities=()

# Process each vulnerability
echo "$vulnerabilities" | jq -c '.' | while read -r vulnerability; do
  title=$(echo "$vulnerability" | jq -r '.title')
  severity=$(echo "$vulnerability" | jq -r '.severity')
  name=$(echo "$vulnerability" | jq -r '.name')
  description=$(echo "$vulnerability" | jq -r '.description')
  affected_version=$(echo "$vulnerability" | jq -r '.affected_version')
  fixed_version=$(echo "$vulnerability" | jq -r '.fixed_version')
  security_severity=$(echo "$vulnerability" | jq -r '.security_severity')
  help_uri=$(echo "$vulnerability" | jq -r '.help_uri')
  purls=$(echo "$vulnerability" | jq -r '.purls | join("\n- ")')

  body=$(cat <<EOF
### Vulnerability Details
- **Name**: $name
- **Description**: 
  $description
- **Affected Version**: $affected_version
- **Fixed Version**: $fixed_version
- **CVSS V3 Severity**: $severity
- **Security Severity**: $security_severity
- **Help URI**: $help_uri
**Affected Packages**:
- $purls

💡 This issue was automatically created by GitHub workflow using the Docker Scout output.
EOF
)

  # Initialize labels with mandatory ones
  labels="vulnerability"
  if [[ -n "$INPUT_PROJECT" ]]; then
    labels="$labels,$INPUT_PROJECT"
  fi
  if [[ "$severity" =~ ^(critical|high|medium|low)$ ]]; then
    labels="$labels,$severity"
  fi

  # Check if the issue already exists
  existing_issue=$(echo "$existing_issues" | jq -r --arg TITLE "$title" '.[] | select(.title == $TITLE)')
  
  if [ -n "$existing_issue" ]; then
    issue_number=$(echo "$existing_issue" | jq -r '.number')
    issue_state=$(echo "$existing_issue" | jq -r '.state')
    current_labels=$(echo "$existing_issue" | jq -r '.labels[].name' | tr '\n' ',' | sed 's/,$//')
    update_issue "$issue_number" "$title" "$body" "$labels" "$issue_state" "$current_labels"
  else
    create_issue "$title" "$body" "$labels"
  fi
  
  # Add the title to the current vulnerabilities array
  current_vulnerabilities+=("$title")
done

# After processing all vulnerabilities, convert current_vulnerabilities array to JSON
current_vulnerabilities_json=$(printf '%s\n' "${current_vulnerabilities[@]}" | jq -R . | jq -s .)

# Process existing issues that are not in the current vulnerabilities
echo "$existing_issues" | jq -c '.[]' | while read -r issue; do
  issue_title=$(echo "$issue" | jq -r '.title')
  issue_number=$(echo "$issue" | jq -r '.number')
  issue_state=$(echo "$issue" | jq -r '.state')
  
  # Check if the issue is in the current vulnerabilities
  if ! echo "$current_vulnerabilities_json" | jq -e --arg TITLE "$issue_title" 'contains([$TITLE])' > /dev/null; then
    if [ "$issue_state" = "open" ] && [ "$INPUT_ALLOW_CLOSING" = "true" ]; then
      gh issue close "$issue_number" --comment "This issue has been closed because it is no longer present in the latest scan."
      echo "Closed issue: $issue_title"
    fi
  fi
done