FROM ubuntu:20.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    dovecot-core \
    dovecot-imapd \
    dovecot-pop3d \
    dovecot-lmtpd \
    && rm -rf /var/lib/apt/lists/*

# Create vmail user/group
RUN groupadd -g 5000 vmail && \
    useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m

# Create mail directories
RUN mkdir -p /var/mail/vhosts && \
    chown -R vmail:vmail /var/mail/vhosts && \
    chmod -R 777 /var/mail/vhosts

# Copy configs
COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY users /etc/dovecot/users

# Expose ports
EXPOSE 143 993 110 995

# Start Dovecot
CMD ["/usr/sbin/dovecot", "-F"]
