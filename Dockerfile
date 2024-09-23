FROM debian:bookworm
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl xz-utils ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/
COPY src/ ./src/
COPY build* ./
RUN curl -O https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz && \
xz --decompress zig-linux-x86_64-0.13.0.tar.xz && tar -xf zig-linux-x86_64-0.13.0.tar && \
./zig-linux-x86_64-0.13.0/zig build -Doptimize=ReleaseSafe --summary all

FROM debian:stable-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/
COPY --from=0 /tmp/zig-out/bin/zgroup .
ENTRYPOINT ["/app/zgroup"]
CMD ["group1", "0.0.0.0:8080"]
