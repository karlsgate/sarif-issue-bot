FROM alpine:latest

# Install necessary packages
RUN apk add --no-cache bash curl jq git github-cli

# Set the working directory
WORKDIR /usr/src/app

COPY entrypoint.sh .

RUN dos2unix entrypoint.sh && chmod +x entrypoint.sh

# Run the script
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]