# SARIF Issue Bot

A GitHub Action to create and manage issues based on SARIF output using GitHub CLI.

## Description

This action processes SARIF (Static Analysis Results Interchange Format) files and creates or updates GitHub issues based on the vulnerabilities found. It's designed to work with security scanning tools that produce SARIF output, such as Docker Scout.

**Note:** This action has currently only been tested with CVE (Common Vulnerabilities and Exposures) data. Its behavior with other types of SARIF data may vary.

## Features

- Creates issues for new vulnerabilities
- Updates existing issues with new information
- Closes resolved issues (optional)
- Reopens previously closed issues if vulnerabilities reappear (optional)
- Adds severity labels to issues
- Supports custom labels

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `github-token` | GitHub token for authentication | Yes | N/A |
| `sarif-file` | Path to the SARIF file | Yes | N/A |
| `issue-title-replacement` | String to be included in the issue title, typically the Docker image name | Yes | N/A |
| `label` | Additional label added to issue | No | '' |
| `allow-reopening` | Allow reopening of previously closed issues | No | true |
| `allow-closing` | Allow closing of resolved issues | No | true |

### Understanding `issue-title-replacement`

The `issue-title-replacement` input is used to customize the title of the issues created by this action. It's typically set to the name of the Docker image being scanned. This allows for easy identification of which image or component a particular vulnerability is associated with.

For example, if you set `issue-title-replacement` to `myapp:latest`, the issue titles will be formatted as:

```
Vulnerability (SEVERITY): VULNERABILITY_ID @ myapp:latest
```

Another example is using just the image name without the tag:

```yaml
- name: Run SARIF Issue Bot
  uses: karlsgate/sarif-issue-bot@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    sarif-file: path/to/sarif-output.json
    issue-title-replacement: your-docker-image
    label: custom-label
```

The title of the issues will be formatted as:

```
Vulnerability (SEVERITY): VULNERABILITY_ID @ your-docker-image
```

Or you can use the product name:

```yaml
- name: Run SARIF Issue Bot
  uses: karlsgate/sarif-issue-bot@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    sarif-file: path/to/sarif-output.json
    issue-title-replacement: your-product
    label: custom-label
```

The title of the issues will be formatted as:

```
Vulnerability (SEVERITY): VULNERABILITY_ID @ your-product
```


This format helps in quickly identifying which image version is affected by a particular vulnerability.

## Usage

To use this action in your workflow, add the following step:

```yaml
- name: Run SARIF Issue Bot
  uses: karlsgate/sarif-issue-bot@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    sarif-file: path/to/sarif-output.json
    issue-title-replacement: your-docker-image
    label: custom-label
```

## Example Workflow

Here's an example of how to integrate this action into a workflow that runs Docker Scout and then processes the SARIF output:

```yaml
name: Security Scan and Issue Management

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  
jobs:
  scan-and-manage-issues:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run Docker Scout
      uses: docker/scout-action@v1
      with:
        command: cves
        image: your-image:tag
        output-file: scout-results.sarif
        dockerhub-user: ${{ secrets.DOCKERHUB_USER }} # For authentication to Docker Hub, or you can use the docker/login-action before this step
        dockerhub-password: ${{ secrets.DOCKERHUB_PASSWORD }} # For authentication to Docker Hub, or you can use the docker/login-action before this step
        registry-user: ${{ secrets.REGISTRY_USER }} # If you're pulling from a private registry like ACR or ECR
        registry-password: ${{ secrets.REGISTRY_PASSWORD }} # If you're pulling from a private registry like ACR or ECR

    - name: Run SARIF Issue Bot
      uses: karlsgate/sarif-issue-bot@v1
      with:
        github-token: ${{ secrets.GITHUB_TOKEN }}
        sarif-file: scout-results.sarif
        issue-title-replacement: your-image or product
        label: docker-security
```


## Limitations

- This action has only been tested with CVE data generated by Docker Scout. Its effectiveness with other types of SARIF data or from other tools has not been verified.
- The action assumes a specific structure in the SARIF file. If you're using a tool other than Docker Scout, you may need to adjust the SARIF parsing logic in the action's script.
- The action currently matches vulnerabilities based on the title of the issue using a simple string comparison. This may lead to false positives if the title format changes (e.g., due to a user updating the title), or if the same vulnerability is reported with a slightly different ID (e.g., `CVE-2023-1234` vs. `CVE-2023-1234-1`).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any problems or have any questions, please open an issue in this repository.