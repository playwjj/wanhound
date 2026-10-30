# WanHound uses plain TCP connect() probes — no raw sockets, so the
# container needs no NET_RAW or other capabilities.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/wanhound ./cmd/wanhound

FROM alpine:3.20
RUN adduser -D -H wanhound
COPY --from=build /out/wanhound /usr/local/bin/wanhound
USER wanhound
VOLUME ["/home/wanhound/.local/share/wanhound"]
ENTRYPOINT ["wanhound"]
CMD ["--help"]
