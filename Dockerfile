FROM mcr.microsoft.com/dotnet/sdk:8.0 AS csharp
WORKDIR /src
COPY SharpSocks.csproj .
RUN dotnet restore
COPY Common/ Common/
COPY Agent/ Agent/
COPY gen-ps1.sh .
RUN dotnet publish -c Release -f net452 -o /dist/agent/net452 --no-restore && \
    dotnet publish -c Release -f net472 -o /dist/agent/net472 --no-restore && \
    find /dist/agent -type f ! -name '*.exe' -delete && \
    bash gen-ps1.sh /dist/agent

FROM golang:latest AS golang
WORKDIR /src
COPY sharpsocks-server/ .
ENV CGO_ENABLED=0
RUN for t in linux-amd64 linux-arm64 windows-amd64 windows-arm64 darwin-amd64 darwin-arm64; do \
      os=${t%%-*}; arch=${t##*-}; ext=; \
      [ "$os" = "windows" ] && ext=.exe; \
      echo "building $t"; \
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" \
        -o /dist/server/$t/sharpsocks-server$ext .; \
    done

FROM busybox
COPY --from=csharp /dist/ /dist/
COPY --from=golang /dist/ /dist/
