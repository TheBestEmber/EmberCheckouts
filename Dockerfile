# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S ember && adduser -S -G ember ember
WORKDIR /app
COPY --from=build /out/api /app/
USER ember
EXPOSE 8080
ENTRYPOINT ["/app/api"]
