FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

COPY challenges /challenge/
COPY flag.txt /challenge/

RUN chmod +x /challenge/challenge

RUN useradd -m ctf
USER ctf

EXPOSE 9999

CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/challenge/challenge"]
