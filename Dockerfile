FROM golang:alpine as builder

WORKDIR /build
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build

FROM alpine:latest
COPY --from=builder /build/go-dnscollector .
COPY /build/config.yml config.yml
EXPOSE 6000/tcp 8080/tcp
ENTRYPOINT ["/go-dnscollector"]
CMD ["config.yml"]