FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache bash curl jq git github-cli gawk

# Set the working directory
WORKDIR /usr/src/app

COPY entrypoint.sh issue_template.md ./test-files ./

RUN dos2unix issue_template.md && \
    dos2unix entrypoint.sh && \
    chmod +x entrypoint.sh

# Run the script
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]