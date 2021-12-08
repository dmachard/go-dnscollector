FROM golang:alpine as builder

ARG VERSION

WORKDIR /build
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-X 'main.Version=$VERSION'"


FROM alpine:latest

RUN mkdir -p /etc/dnscollector/ /var/dnscollector/

COPY --from=builder /build/go-dnscollector /bin/go-dnscollector
COPY --from=builder /build/config.yml ./etc/dnscollector/config.yml

RUN addgroup -g 1000 dnscollector && adduser -D -H -G dnscollector -u 1000 -S dnscollector 
RUN chown dnscollector:dnscollector /var/dnscollector /etc/dnscollector
USER dnscollector

EXPOSE 6000/tcp 8080/tcp

ENTRYPOINT ["/bin/go-dnscollector"]

CMD ["-config", "/etc/dnscollector/config.yml"]