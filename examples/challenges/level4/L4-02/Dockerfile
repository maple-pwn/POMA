FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge


COPY . /challenge/
RUN chmod +x /challenge/challenge

EXPOSE 20402

CMD ["socat", "TCP-LISTEN:20402,reuseaddr,fork", "EXEC:/challenge/challenge"]
