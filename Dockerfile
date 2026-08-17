FROM golang:1.24.4 AS builder

COPY . /src

WORKDIR /src

RUN apt-get update && \
    apt-get install -y gcc libc6-dev

RUN GOPROXY=https://goproxy.cn go mod download

RUN go build -o /src/main .


FROM debian:bookworm-slim

ENV TZ=Asia/Shanghai

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    netbase \
    libc6 && \
    rm -rf /var/lib/apt/lists/*


COPY --from=builder /src/main /app/main

WORKDIR /app

CMD ["./main"]