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

FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
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

FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /out/secrets-bridge-agent /usr/local/bin/secrets-bridge-agent
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/secrets-bridge-agent"]
