#!/bin/ash

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

echo "" > sarif_titles.txt
echo "" > sarif_closed_titles.txt

echo "" > sarif_titles_with_issue_numbers.txt
echo "" > sarif_closed_titles_with_issue_numbers.txt

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
  
  label_exists=$(gh label list --json name --jq '.[] | select(.name == "'"$label"'")')

  if [ -z "$label_exists" ]; then
    echo "⏳ Label $label will be created"
    gh label create "$label" --color "$color" --description "$description" > /dev/null 2>&1 || echo "❌ Failed to create label: $label"
    echo "✅ Label $label was created successfully"
  else
    echo "✅ Label $label already exists"
  fi
}

# Function to create a new issue
create_issue() {
  local title="$1"
  local body="$2"
  local labels="$3"

  # Use printf to preserve newlines in the body
  url=$(printf "%s" "$body" | gh issue create --title "$title" --body-file - --label "$labels")
  issue_number=$(echo "$url" | grep -oE '[0-9]+$')

  echo "Issue #$issue_number: [$title]($url)" >> sarif_titles_with_issue_numbers.txt
  echo "🆕 Created issue #$issue_number: '$title' with labels: $labels"
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
    gh issue reopen "$issue_number" > /dev/null 2>&1
    gh issue comment "$issue_number" --body "This issue has been reopened because it is present in the latest scan." > /dev/null 2>&1
    echo "🔓 Reopened issue: $title"
  fi

  # Add new labels
  for label in $(echo "$new_labels" | tr ',' ' '); do
    if ! echo "$current_labels" | grep -q "$label"; then
      gh issue edit "$issue_number" --add-label "$label" > /dev/null 2>&1
      echo "🏷️Added label: $label to issue #$issue_number"
    fi
  done

  # Remove old labels that are no longer applicable
  for label in $(echo "$current_labels" | tr ',' ' '); do
    if ! echo "$new_labels" | grep -q "$label"; then
      gh issue edit "$issue_number" --remove-label "$label" > /dev/null 2>&1
      echo "❌ Removed label: $label from issue #$issue_number"
    fi
  done

  echo "✏️ Updated issue #$issue_number: $title with labels: $new_labels"
}

# Function to close an issue
close_issue() {
  local issue_number="$1"
  local title="$2"
  local url="$3"

  gh issue close "$issue_number" --comment "This issue has been closed because it is no longer present in the latest scan." > /dev/null 2>&1
  echo "Issue #$issue_number: [$title]($url)" >> sarif_closed_titles_with_issue_numbers.txt
  echo "🔒 Closed issue #$issue_number: $title"
}

# Function to reopen an issue
reopen_issue() {
  local issue_number="$1"
  local title="$2"

  gh issue reopen "$issue_number" > /dev/null 2>&1
  gh issue comment "$issue_number" --body "This issue has been reopened because it is present in the latest scan." > /dev/null 2>&1
  echo "🔓 Reopened issue #$issue_number: $title"
}

replace_placeholder() {
    local template="$1"
    local placeholder="$2"
    local value="$3"
    
    awk -v p="$placeholder" -v v="$value" '
    BEGIN {
        RS = ORS = "\n"
        gsub(/[\\&]/, "\\\\&", v)
    }
    {
        gsub(p, v)
        print
    }' <<EOF
$template
EOF
}

# Function to process vulnerabilities
process_vulnerabilities() {
  
  # Create necessary labels if they don't exist
  create_label_if_not_exists "security" "d93f0b" "Security advisory, incident, issue, or vulnerability"
  create_label_if_not_exists "critical" "ff0000" "Critical priority issue"
  create_label_if_not_exists "high" "ff6600" "High priority issue"
  create_label_if_not_exists "medium" "ffdd00" "Medium priority issue"
  create_label_if_not_exists "low" "0000ff" "Low priority issue"

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
    purls=$(echo "$vulnerability" | jq -r '.purls | map("   - " + .) | join("\n")')

    # Use the replace_placeholder function to update the issue template
    body="$ISSUE_TEMPLATE"
    body=$(replace_placeholder "$body" "{{name}}" "$name")
    body=$(replace_placeholder "$body" "{{description}}" "$description")
    body=$(replace_placeholder "$body" "{{affected_version}}" "$affected_version")
    body=$(replace_placeholder "$body" "{{fixed_version}}" "$fixed_version")
    body=$(replace_placeholder "$body" "{{severity}}" "$severity")
    body=$(replace_placeholder "$body" "{{security_severity}}" "$security_severity")
    body=$(replace_placeholder "$body" "{{help_uri}}" "$help_uri")
    body=$(replace_placeholder "$body" "{{purls}}" "$purls")
    body=$(echo "$body" | sed 's/{{[^}]*}}//g')

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

    echo "⏳ Processing: $title"

    # Check if the issue already exists
    existing_issue=$(echo "$existing_issues" | jq -r --arg TITLE "$title" '.[] | select(.title == $TITLE)')
    
    if [ -n "$existing_issue" ]; then
      issue_number=$(echo "$existing_issue" | jq -r '.number')
      issue_state=$(echo "$existing_issue" | jq -r '.state')
      current_labels=$(echo "$existing_issue" | jq -r '.labels[].name' | tr '\n' ',' | sed 's/,$//')
      url=$(echo "$existing_issue" | jq -r '.url')

      if [ "$issue_state" = "CLOSED" ] && [ "$INPUT_ALLOW_REOPENING" = true ]; then
        reopen_issue "$issue_number" "$title"
      fi

      update_issue "$issue_number" "$title" "$body" "$labels" "$issue_state" "$current_labels"
      echo "Issue #$issue_number: [$title]($url)" >> sarif_titles_with_issue_numbers.txt
    else
      create_issue "$title" "$body" "$labels"
    fi
  done
}


if [ -n "$INPUT_LABEL" ]; then
  random_color=$(generate_random_color)
  create_label_if_not_exists "$INPUT_LABEL" "$random_color" "$INPUT_ISSUE_TITLE_REPLACEMENT"
fi

# Read vulnerabilities from SARIF file
vulnerabilities=$(jq -r '.runs[0].tool.driver.rules[] | {
  title: "Vulnerability (\(.properties.cvssV3_severity)): \(.id) @ '"$INPUT_ISSUE_TITLE_REPLACEMENT"'",
  severity: .properties.cvssV3_severity,
  name: "\(.name) - \(.id)",
  description: .help.text,
  affected_version: .properties.affected_version,
  fixed_version: .properties.fixed_version,
  security_severity: .properties."security-severity",
  help_uri: .helpUri,
  purls: .properties.purls
}' "$INPUT_SARIF_FILE")

# Fetch all issues with the 'security' label, both open and closed
existing_issues=$(gh issue list --label security --label $INPUT_LABEL  --state all --json number,title,state,labels,url 2> /dev/null)

# Process vulnerabilities only if there are any
if [ -n "$vulnerabilities" ]; then
  process_vulnerabilities
else
  echo "🔍 No vulnerabilities found to process."
fi

# Check for issues to close
if [ "$INPUT_ALLOW_CLOSING" = true ]; then
  echo "$existing_issues" | jq -c '.[] | select(.state == "OPEN")' | while read -r issue; do
    issue_number=$(echo "$issue" | jq -r '.number')
    issue_title=$(echo "$issue" | jq -r '.title')
    url=$(echo "$issue" | jq -r '.url')
    
    echo "🔍 Checking issue #$issue_number: $issue_title"
    normalized_issue_title=$(echo "$issue_title" | tr -s ' ' | xargs)
    echo "⚖️ Comparing normalized issue title: '$normalized_issue_title' to original issue title from GitHub: '$issue_title'"

    if grep -i -Fxq "$normalized_issue_title" sarif_titles.txt; then
      echo "👍 Keeping open issue #$issue_number: $issue_title"
    else
      echo "👋 Closing issue #$issue_number: $issue_title"
      echo "$normalized_issue_title" >> sarif_closed_titles.txt
      close_issue "$issue_number" "$normalized_issue_title" "$url"
    fi
  done
fi
echo "✅ Done processing vulnerabilities"

OPEN_ISSUES=$(cat sarif_titles_with_issue_numbers.txt)
CLOSED_ISSUES=$(cat sarif_closed_titles_with_issue_numbers.txt)

if [[ "$OPEN_ISSUES" =~ ^[[:space:]]*$ ]]; then
  # Trim whitespace and newlines
  OPEN_ISSUES=$(echo "$OPEN_ISSUES" | xargs)
fi

if [[ "$CLOSED_ISSUES" =~ ^[[:space:]]*$ ]]; then
  # Trim whitespace and newlines
  CLOSED_ISSUES=$(echo "$CLOSED_ISSUES" | xargs)
fi

if [ -n "$OPEN_ISSUES" ]; then
  # Output to the build step (console)
  echo ""  
  echo "📃🔓 Here are the currently open vulnerability issue titles for $INPUT_ISSUE_TITLE_REPLACEMENT:"
  echo "$OPEN_ISSUES"
  
  # Output to the GitHub Actions summary
  echo "## 📃🔓 Open Vulnerability Issues for $INPUT_ISSUE_TITLE_REPLACEMENT" >> $GITHUB_STEP_SUMMARY
  echo "$OPEN_ISSUES" >> $GITHUB_STEP_SUMMARY
fi

if [ -n "$CLOSED_ISSUES" ]; then
  # Output to the build step (console)
  echo ""
  echo "📃🔒 Here are the closed vulnerability issue titles for $INPUT_ISSUE_TITLE_REPLACEMENT:"
  echo "$CLOSED_ISSUES"
  
  # Output to the GitHub Actions summary
  echo "## 📃🔓 Closed Vulnerability Issues for $INPUT_ISSUE_TITLE_REPLACEMENT" >> $GITHUB_STEP_SUMMARY
  echo "$CLOSED_ISSUES" >> $GITHUB_STEP_SUMMARY
fi


# Clean up
rm -f sarif_titles.txt
rm -f sarif_closed_titles.txt
rm -f sarif_titles_with_issue_numbers.txt
rm -f sarif_closed_titles_with_issue_numbers.txt