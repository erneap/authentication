##############################
# Step 1 build executable binary
##############################
FROM golang:alpine AS builder

## Install git
RUN apk update && apk add --no-cache git

ENV USER=scheduler
ENV UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR $GOPATH/src/scheduler2/authentication-api/
COPY . .

# Fetch Dependencies
RUN go get -d -v

# build binary
RUN go build -o /go/bin/authentication-api

################################
# Step 2 Build the small image
################################
FROM debian:bookworm-slim

RUN apt update && apt install ca-certificates -y

ADD . /data/reports
ADD . /data/logs

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder /go/bin/authentication-api /go/bin/authentication-api

USER scheduler:scheduler

EXPOSE 6002

ENTRYPOINT [ "/go/bin/authentication-api" ]