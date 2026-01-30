FROM ubuntu:20.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install Postfix
RUN apt-get update && apt-get install -y \
    postfix \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Config
COPY main.cf /etc/postfix/main.cf
COPY master.cf /etc/postfix/master.cf
COPY vdomains /etc/postfix/vdomains
COPY valias /etc/postfix/valias

# Setup vmail user (uid 5000) to match Dovecot
RUN groupadd -g 5000 vmail && \
    useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m

# Create vhosts dir
RUN mkdir -p /var/mail/vhosts && \
    chown -R vmail:vmail /var/mail/vhosts && \
    chmod -R 770 /var/mail/vhosts

# Ports
EXPOSE 25

# Entrypoint
# Run Postfix in foreground
CMD ["sh", "-c", "postfix start-fg"]
