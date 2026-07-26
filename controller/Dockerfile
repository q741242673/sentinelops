FROM golang:1.23 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sentinelops-remediation-controller \
    ./cmd/controller

FROM scratch
COPY --from=build /out/sentinelops-remediation-controller /sentinelops-remediation-controller
USER 65532:65532
ENTRYPOINT ["/sentinelops-remediation-controller"]
