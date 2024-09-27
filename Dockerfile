FROM kassany/alpine-ziglang:0.13.0
WORKDIR /tmp/
COPY src/ ./src/
COPY build* ./
RUN zig build -Doptimize=ReleaseFast --summary all
# RUN zig build --summary all

FROM debian:stable-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/
COPY --from=0 /tmp/zig-out/bin/zgroup .
ENTRYPOINT ["/app/zgroup"]
CMD ["group1", "0.0.0.0:8080"]
