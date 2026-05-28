# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Secrets Bridge agent. Runtime image is
# distroless/static so the container has no shell, no package manager,
# and runs as nonroot. The whole point of the agent is to stay small
# and trivially deployable inside customer boundaries.

FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.buildVersion=${BUILD_VERSION}" \
      -o /out/agent \
      ./cmd/agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent /usr/local/bin/agent
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/agent"]
