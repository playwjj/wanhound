# WanHound uses plain TCP connect() probes — no raw sockets, so the
# container needs no NET_RAW or other capabilities.
FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/wanhound ./cmd/wanhound

FROM alpine:3.22
RUN adduser -D wanhound \
 && mkdir -p /home/wanhound/.local/share/wanhound \
 && chown -R wanhound:wanhound /home/wanhound
COPY --from=build /out/wanhound /usr/local/bin/wanhound
USER wanhound
ENV WANHOUND_DATA=/home/wanhound/.local/share/wanhound
VOLUME ["/home/wanhound/.local/share/wanhound"]
EXPOSE 8687
ENTRYPOINT ["wanhound"]
CMD ["--help"]
