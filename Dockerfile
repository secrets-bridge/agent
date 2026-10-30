# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Secrets Bridge agent. Runtime image is
# distroless/static so the container has no shell, no package manager,
# and runs as nonroot. The whole point of the agent is to stay small
# and trivially deployable inside customer boundaries.
#
# With no arguments the image runs the agent. The same binary carries the
# operator subcommands: `docker run -i --rm <image> enroll ...` and
# `docker run -i --rm <image> rotate-key ...`.

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.buildVersion=${BUILD_VERSION}" \
      -o /out/secrets-bridge-agent \
      ./cmd/agent

FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/secrets-bridge-agent /usr/local/bin/secrets-bridge-agent
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/secrets-bridge-agent"]
