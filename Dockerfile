# Use a lightweight base image with bash and curl
FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache bash curl jq git

# Install GitHub CLI
RUN curl -fsSL https://github.com/cli/cli/releases/latest/download/gh_2.57.0_linux_amd64.tar.gz | tar xz && \
    mv gh_2.57.0_linux_amd64/bin/gh /usr/local/bin/

# Set the working directory
WORKDIR /usr/src/app

# Copy the script into the container
COPY entrypoint.sh .

# Make the script executable
RUN chmod +x entrypoint.sh

# Run the script
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]