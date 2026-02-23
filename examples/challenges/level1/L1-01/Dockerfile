FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge


COPY . /challenge/
RUN chmod +x /challenge/challenge

RUN useradd -m ctf
USER ctf

EXPOSE 20101

CMD ["socat", "TCP-LISTEN:20101,reuseaddr,fork", "EXEC:/challenge/challenge"]
