"""Sigil ML sidecar — gRPC server (DESIGN §9.9).

Implements the ``MlSidecar`` service from ``proto/sigil_ml.proto``:

* ``Health`` — liveness + version.
* ``Embed``  — event JSON strings → dense vectors (hashing fallback, or a real
  sentence-transformer when the ``model`` extra is installed).
* ``Score``  — subgraph → anomaly/causal scores. Placeholder until the GNN /
  causal model lands in Phase 4.

Run with::

    python -m sidecar.server         # or: sigil-sidecar

Bulk event/tensor transfer over Arrow Flight is a later addition; this gRPC
surface covers control + small batches.
"""

from __future__ import annotations

from concurrent import futures

GRPC_ENDPOINT = "0.0.0.0:50051"


def _build_server(endpoint: str = GRPC_ENDPOINT):
    import grpc

    from ._codegen import load
    from .embedder import load_embedder

    pb2, pb2_grpc = load()
    embedder = load_embedder()

    class MlSidecar(pb2_grpc.MlSidecarServicer):
        def Health(self, request, context):
            return pb2.HealthReply(ok=True, version="0.0.0-phase3")

        def Embed(self, request, context):
            vectors = [
                pb2.FloatVector(values=embedder.embed(text)) for text in request.event_json
            ]
            return pb2.EmbedReply(vectors=vectors)

        def Score(self, request, context):
            # Placeholder scores until the GNN/causal model (Phase 4, §9.5).
            return pb2.ScoreReply(anomaly=0.0, causal=0.0)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb2_grpc.add_MlSidecarServicer_to_server(MlSidecar(), server)
    server.add_insecure_port(endpoint)
    return server


def main() -> None:
    try:
        server = _build_server()
    except ImportError as exc:  # grpcio / grpcio-tools not installed
        print(f"[sidecar] missing dependency: {exc}")
        print("[sidecar] install with: pip install -e ml-sidecar")
        return
    server.start()
    print(f"[sidecar] Sigil ML sidecar serving gRPC on {GRPC_ENDPOINT}")
    server.wait_for_termination()


if __name__ == "__main__":
    main()
