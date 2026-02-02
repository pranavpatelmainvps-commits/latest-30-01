FROM almalinux:8

# Install dependencies
RUN yum install -y openssh-server perl procps net-tools iproute sysvinit-tools libnsl && \
    yum clean all

# Configure SSH
RUN mkdir /var/run/sshd && \
    ssh-keygen -A && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config

# Files will be copied from the build context (project root)
# The docker-compose context will be set to the project root
COPY PowerMTA.rpm /tmp/
COPY pmtad /tmp/
COPY pmtahttpd /tmp/
COPY license /tmp/

# Install PMTA
# We do a basic installation here so it's ready to use. 
# The existing install script in the repo is designed for a fresh OS, 
# but we can pre-install in the docker image to save time.
RUN if [ -f /tmp/PowerMTA.rpm ]; then \
    rpm -Uvh --nosignature --nodigest /tmp/PowerMTA.rpm; \
    fi

# Copy binaries if they exist (overwrite RPM installed ones if needed, based on user's repo structure)
RUN if [ -f /tmp/pmtad ]; then cp /tmp/pmtad /usr/sbin/pmtad; fi && \
    if [ -f /tmp/pmtahttpd ]; then cp /tmp/pmtahttpd /usr/sbin/pmtahttpd; fi && \
    chmod 755 /usr/sbin/pmtad /usr/sbin/pmtahttpd

# License
RUN mkdir -p /etc/pmta && \
    if [ -f /tmp/license ]; then cp /tmp/license /etc/pmta/license; fi && \
    chmod 600 /etc/pmta/license

# Create logs directory
RUN mkdir -p /var/log/pmta /var/spool/pmta && \
    chown -R pmta:pmta /var/log/pmta /var/spool/pmta || true

# Expose ports
# 22: SSH
# 25: SMTP
# 8080: Web Monitor
EXPOSE 22 25 8080

COPY docker/pmta/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
