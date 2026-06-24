"""Compile the Sigil ML proto at runtime so no generated code is committed.

Uses ``grpc_tools.protoc`` to generate the ``*_pb2`` / ``*_pb2_grpc`` modules
from ``proto/sigil_ml.proto`` into a temp dir, then imports them.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile


def load():
    """Return ``(pb2, pb2_grpc)`` for the Sigil ML service."""
    from grpc_tools import protoc

    # `SIGIL_PROTO_DIR` overrides the location (used in the container image);
    # otherwise fall back to the repo layout (proto/ two levels up).
    proto_dir = pathlib.Path(
        os.environ.get("SIGIL_PROTO_DIR", pathlib.Path(__file__).resolve().parents[2] / "proto")
    )
    proto_file = proto_dir / "sigil_ml.proto"
    if not proto_file.exists():
        raise FileNotFoundError(f"proto not found at {proto_file}")

    out_dir = tempfile.mkdtemp(prefix="sigil_ml_proto_")
    rc = protoc.main(
        [
            "protoc",
            f"-I{proto_dir}",
            f"--python_out={out_dir}",
            f"--grpc_python_out={out_dir}",
            str(proto_file),
        ]
    )
    if rc != 0:
        raise RuntimeError(f"protoc failed with exit code {rc}")

    if out_dir not in sys.path:
        sys.path.insert(0, out_dir)
    import sigil_ml_pb2 as pb2  # type: ignore
    import sigil_ml_pb2_grpc as pb2_grpc  # type: ignore

    return pb2, pb2_grpc
