FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libbpf1 procps openssh-server

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
	sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

RUN useradd -ms /bin/bash bocchi

COPY id_ed25519.pub /home/bocchi/.ssh/authorized_keys

RUN chown -R bocchi:bocchi /home/bocchi/.ssh && \
    chmod 700 /home/bocchi/.ssh && \
    chmod 600 /home/bocchi/.ssh/authorized_keys

COPY compose.yml Dockerfile entrypoint.sh loader readflag flag /

RUN chmod 4755 readflag && \
    chmod 755 loader entrypoint.sh && \
    chmod 400 /flag

CMD ["/entrypoint.sh"]
