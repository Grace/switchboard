# Build
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/switchboard ./cmd/switchboard

# Run
#
# Static, non-root, no shell. This image serves the Bedrock path: local models
# need a llama.cpp process and GPU access, which is a host concern, not a
# container one. Run the binary directly on the machine for those.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/switchboard /switchboard
EXPOSE 11435
USER nonroot:nonroot
ENTRYPOINT ["/switchboard"]
CMD ["serve"]
