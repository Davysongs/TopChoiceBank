FROM golang:1.25 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/api ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/worker ./cmd/worker \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/scheduler ./cmd/scheduler

FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /out/api /app/api
COPY --from=builder /out/worker /app/worker
COPY --from=builder /out/scheduler /app/scheduler

EXPOSE 8080
CMD ["/app/api"]
