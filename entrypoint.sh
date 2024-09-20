#!/bin/sh

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
INPUT_ISSUE_TITLE_REPLACEMENT="$3"
INPUT_LABEL="$4"
INPUT_ALLOW_REOPENING="${5:-true}"
INPUT_ALLOW_CLOSING="${6:-true}"

# Read the issue template from the file
ISSUE_TEMPLATE=$(cat /usr/src/app/issue_template.md)

# Configure Git to trust the workspace directory
git config --global --add safe.directory /github/workspace

# Authenticate with GitHub CLI
echo "$INPUT_GITHUB_TOKEN" | gh auth login --with-token

# Function to generate a random color
generate_random_color() {
  printf '%06X\n' "$((RANDOM % 16777215))"
}

# Function to create a label if it doesn't exist
create_label_if_not_exists() {
  local label="$1"
  local color="$2"
  local description="$3"
  
  if ! gh label list | grep -q "$label"; then
    gh label create "$label" --color "$color" --description "$description" || echo "Failed to create label: $label"
  fi
}

# Function to create a new issue
create_issue() {
  local title="$1"
  local body="$2"
  local labels="$3"

  # Use printf to preserve newlines in the body
  printf "%s" "$body" | gh issue create --title "$title" --body-file - --label "$labels"
  echo "Created issue: $title with labels: $labels"
}

# Function to update an existing issue
update_issue() {
  local issue_number="$1"
  local title="$2"
  local body="$3"
  local new_labels="$4"
  local issue_state="$5"
  local current_labels="$6"

  if [ "$issue_state" = "closed" ] && [ "$INPUT_ALLOW_REOPENING" = true ]; then
    gh issue reopen "$issue_number"
    gh issue comment "$issue_number" --body "This issue has been reopened because it is present in the latest scan."
    echo "Reopened issue: $title"
  fi

  # Add new labels
  for label in $(echo "$new_labels" | tr ',' ' '); do
    if ! echo "$current_labels" | grep -q "$label"; then
      gh issue edit "$issue_number" --add-label "$label"
      echo "Added label: $label to issue #$issue_number"
    fi
  done

  # Remove old labels that are no longer applicable
  for label in $(echo "$current_labels" | tr ',' ' '); do
    if ! echo "$new_labels" | grep -q "$label"; then
      gh issue edit "$issue_number" --remove-label "$label"
      echo "Removed label: $label from issue #$issue_number"
    fi
  done

  echo "Updated issue #$issue_number: $title with labels: $new_labels"
}

# Function to close an issue
close_issue() {
  local issue_number="$1"
  local title="$2"

  gh issue close "$issue_number" --comment "This issue has been closed because it is no longer present in the latest scan."
  echo "Closed issue #$issue_number: $title"
}

# Function to reopen an issue
reopen_issue() {
  local issue_number="$1"
  local title="$2"

  gh issue reopen "$issue_number"
  gh issue comment "$issue_number" --body "This issue has been reopened because it is present in the latest scan."
  echo "Reopened issue #$issue_number: $title"
}

# Function to process vulnerabilities
process_vulnerabilities() {
  echo "" > sarif_titles.txt  # Clear the file at the start

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

    # Use the issue template and replace placeholders with actual values
    body=$(echo "$ISSUE_TEMPLATE" | sed \
      -e "s|{{name}}|$name|g" \
      -e "s|{{description}}|$description|g" \
      -e "s|{{affected_version}}|$affected_version|g" \
      -e "s|{{fixed_version}}|$fixed_version|g" \
      -e "s|{{severity}}|$severity|g" \
      -e "s|{{security_severity}}|$security_severity|g" \
      -e "s|{{help_uri}}|$help_uri|g" \
      -e "s|{{purls}}|$purls|g" \
      -e "s|{{image_name}}|$INPUT_ISSUE_TITLE_REPLACEMENT|g"
    )

    # Initialize labels with mandatory ones
    labels="security"
    if [ -n "$INPUT_LABEL" ]; then
      labels="$labels,$INPUT_LABEL"
    fi
    severity=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
    case "$severity" in
      critical|high|medium|low)
        labels="$labels,$severity"
        ;;
    esac

    # Add the title to the file of SARIF vulnerability titles
    echo "$title" >> sarif_titles.txt

    echo "Processing vulnerability: $title"

    # Check if the issue already exists
    existing_issue=$(echo "$existing_issues" | jq -r --arg TITLE "$title" '.[] | select(.title == $TITLE)')
    
    if [ -n "$existing_issue" ]; then
      issue_number=$(echo "$existing_issue" | jq -r '.number')
      issue_state=$(echo "$existing_issue" | jq -r '.state')
      current_labels=$(echo "$existing_issue" | jq -r '.labels[].name' | tr '\n' ',' | sed 's/,$//')

      if [ "$issue_state" = "CLOSED" ] && [ "$INPUT_ALLOW_REOPENING" = true ]; then
        reopen_issue "$issue_number" "$title"
      fi

      update_issue "$issue_number" "$title" "$body" "$labels" "$issue_state" "$current_labels"
    else
      create_issue "$title" "$body" "$labels"
    fi
  done
}

# Create necessary labels
create_label_if_not_exists "security" "d93f0b" "Security advisory, incident, issue, or vulnerability"
create_label_if_not_exists "critical" "ff0000" "Critical priority issue"
create_label_if_not_exists "high" "ff6600" "High priority issue"
create_label_if_not_exists "medium" "ffdd00" "Medium priority issue"
create_label_if_not_exists "low" "0000ff" "Low priority issue"

if [ -n "$INPUT_LABEL" ]; then
  random_color=$(generate_random_color)
  create_label_if_not_exists "$INPUT_LABEL" "$random_color" "$INPUT_ISSUE_TITLE_REPLACEMENT"
fi

# Read vulnerabilities from SARIF file
vulnerabilities=$(jq -r '.runs[0].tool.driver.rules[] | {
  title: "Vulnerability (\(.properties.cvssV3_severity)): \(.id) @ '"$INPUT_ISSUE_TITLE_REPLACEMENT"'",
  severity: .properties.cvssV3_severity,
  name: .name,
  description: .help.text,
  affected_version: .properties.affected_version,
  fixed_version: .properties.fixed_version,
  security_severity: .properties."security-severity",
  help_uri: .helpUri,
  purls: .properties.purls
}' "$INPUT_SARIF_FILE")

# Fetch all issues with the 'security' label, both open and closed
existing_issues=$(gh issue list --label security --state all --json number,title,state,labels)

# Process vulnerabilities
process_vulnerabilities

echo "SARIF Vulnerability Titles:"
cat sarif_titles.txt

echo "SARIF Vulnerability Titles: $sarif_vulnerability_titles"

# Check for issues to close
if [ "$INPUT_ALLOW_CLOSING" = true ]; then
  echo "$existing_issues" | jq -c '.[] | select(.state == "OPEN")' | while read -r issue; do
    issue_number=$(echo "$issue" | jq -r '.number')
    issue_title=$(echo "$issue" | jq -r '.title')
    
    echo "Checking issue #$issue_number: $issue_title"
    if grep -Fxq "$issue_title" sarif_titles.txt; then
      echo "Keeping open issue #$issue_number: $issue_title"
    else
      echo "Closing issue #$issue_number: $issue_title"
      close_issue "$issue_number" "$issue_title"
    fi
  done
fi

# Clean up
rm sarif_titles.txt