# syntax=docker/dockerfile:1
#
# Sigil ML sidecar — gRPC server (DESIGN §9.9). Ships the deterministic hashing
# embedder so it runs with no model download; SecureBERT is the `model` extra.
#
# Build from the REPO ROOT (needs proto/):
#   docker build -f ml-sidecar/Dockerfile -t sigil-sidecar:latest .

FROM python:3.12-slim AS runtime
WORKDIR /app

# gRPC + the protoc toolchain (the server compiles the proto at startup).
RUN pip install --no-cache-dir "grpcio>=1.60" "grpcio-tools>=1.60"

COPY ml-sidecar/sidecar ./sidecar
COPY proto ./proto

# Tell the codegen where the proto lives inside the image.
ENV SIGIL_PROTO_DIR=/app/proto
EXPOSE 50051

CMD ["python", "-m", "sidecar.server"]
