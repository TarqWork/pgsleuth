#!/bin/bash
set -e

cd /workspace/source/pgsleuth-ebpf-poc

# Resolve pg_config once (used by the pg-ext build). pgrx invokes it
# during compilation and `cargo pgrx package` requires it explicitly.
PG_CONFIG="$(command -v pg_config || true)"

# -----------------------------------------------------------------------------
# Optional backtrace flag — parse $2 / $3 for --backtrace or --full and export
# RUST_BACKTRACE accordingly. Passing nothing leaves RUST_BACKTRACE as set in
# the environment (or unset, which means no backtrace).
#
# Usage:
#   ./build.sh pg-ext --backtrace   # RUST_BACKTRACE=1 (call stack)
#   ./build.sh pg-ext --full        # RUST_BACKTRACE=full (stack + source)
#   ./build.sh all   --backtrace    # also works for the umbrella targets
#
# See: https://doc.rust-lang.org/std/backtrace/index.html
# -----------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --backtrace|-b)
      export RUST_BACKTRACE=1
      echo "[build.sh] RUST_BACKTRACE=1 (call stack on errors)"
      ;;
    --full)
      export RUST_BACKTRACE=full
      echo "[build.sh] RUST_BACKTRACE=full (stack + source snippets)"
      ;;
  esac
done

build_pg_ext() {
  if [ -z "$PG_CONFIG" ]; then
    echo "ERROR: pg_config not found on PATH."
    echo "       The pg-ext build requires postgresql-server-dev-17 and cargo-pgrx"
    echo "       in the rust-dev container. See pgsleuth-pg-ext/README.md."
    return 1
  fi
  if ! command -v cargo-pgrx >/dev/null 2>&1; then
    echo "ERROR: cargo-pgrx not found on PATH."
    echo "       Install with: cargo install --locked cargo-pgrx --version 0.12.9"
    echo "       (must match the pgrx version pinned in pgsleuth-pg-ext/Cargo.toml)."
    return 1
  fi
  # Force pgrx to stage artifacts at a fixed, predictable path **inside
  # the shared build mount** so the ebpf-feasibility container can see
  # them.
  #
  # IMPORTANT: --out-dir is resolved relative to the current working
  # directory. rust-dev's CWD is /workspace/source/pgsleuth-ebpf-poc/
  # (host project tree, NOT the shared mount), so a relative path here
  # would land outside /workspace/build and be invisible to
  # ebpf-feasibility. We anchor to $CARGO_TARGET_DIR (set to
  # /workspace/build/target via docker-compose.yml) to keep the
  # artifacts in the shared mount.
  #
  # install-pg-ext.sh's default PG_EXT_PKG="target/pg-ext-pkg" is the
  # matching relative path from ebpf-feasibility's CWD /workspace/build,
  # which resolves to the same absolute path. Bump both together if you
  # ever change the trailing directory name.
  local PG_EXT_OUT_DIR="${CARGO_TARGET_DIR:-./target}/pg-ext-pkg"
  echo "=== Building Postgres extension (pgsleuth-pg-ext) ==="
  cargo pgrx package --package pgsleuth-pg-ext \
                     --pg-config "$PG_CONFIG" \
                     --out-dir "$PG_EXT_OUT_DIR"
  echo "pg-ext build complete: $PG_EXT_OUT_DIR/"
}

case "${1:-ebpf}" in
  ebpf)
    echo "=== Building eBPF program ==="
    cargo build -Zbuild-std --target bpfel-unknown-none --release -p pgsleuth-ebpf
    echo "eBPF build complete: /workspace/build/target/bpfel-unknown-none/release/pgsleuth-ebpf"
    ;;

  loader)
    echo "=== Building userspace loader ==="
    cargo build --release -p pgsleuth-ebpf-loader
    echo "Loader build complete"
    ;;

  common)
    echo "=== Building common types ==="
    cargo build --release -p pgsleuth-ebpf-common
    echo "Common build complete"
    ;;

  pg-ext)
    build_pg_ext
    ;;

  all)
    echo "=== Building eBPF program ==="
    cargo build -Zbuild-std --target bpfel-unknown-none --release -p pgsleuth-ebpf
    echo "eBPF build complete"

    echo "=== Building userspace loader ==="
    cargo build --release -p pgsleuth-ebpf-loader
    echo "Loader build complete"

    echo "=== Building common types ==="
    cargo build --release -p pgsleuth-ebpf-common
    echo "Common build complete"

    build_pg_ext

    echo "=== All builds complete ==="
    ;;

  clean)
    echo "=== Cleaning build artifacts ==="
    # `cargo clean` removes the entire target/ directory, which covers
    # every workspace member including pgsleuth-pg-ext's staged pkg/.
    cargo clean
    echo "Clean complete"
    ;;

  check)
    echo "=== Checking all packages ==="
    cargo check -p pgsleuth-ebpf
    cargo check -p pgsleuth-ebpf-loader
    cargo check -p pgsleuth-ebpf-common
    if [ -n "$PG_CONFIG" ]; then
      cargo check -p pgsleuth-pg-ext
    else
      echo "Skipping pgsleuth-pg-ext check: pg_config not found (install postgresql-server-dev-17)."
    fi
    echo "Check complete"
    ;;

  test)
    echo "=== Running tests ==="
    cargo test -p pgsleuth-ebpf-common
    cargo test -p pgsleuth-ebpf-loader
    # pgsleuth-pg-ext's #[pg_test] suite needs a managed PG instance
    # initialised by `cargo pgrx init`. Run it via the dedicated target
    # below instead of plain `cargo test`.
    echo "Note: pgsleuth-pg-ext tests are not part of 'test'."
    echo "      Run './build.sh pg-ext-test' to invoke cargo pgrx test."
    echo "Tests complete"
    ;;

  pg-ext-test)
    if [ -z "$PG_CONFIG" ] || ! command -v cargo-pgrx >/dev/null 2>&1; then
      echo "ERROR: pg-ext-test requires pg_config and cargo-pgrx. See pgsleuth-pg-ext/README.md."
      exit 1
    fi
    echo "=== Running pgsleuth-pg-ext #[pg_test] suite (managed PG 17) ==="
    cargo pgrx test pg17 --package pgsleuth-pg-ext
    echo "pg-ext tests complete"
    ;;

  *)
    echo "Usage: $0 <command> [--backtrace|-b | --full]"
    echo ""
    echo "Commands:"
    echo "  ebpf         - Build eBPF kernel program (default)"
    echo "  loader       - Build userspace loader"
    echo "  common       - Build shared types"
    echo "  pg-ext       - Build & package the Postgres extension (pgrx)"
    echo "  all          - Build everything (ebpf, loader, common, pg-ext)"
    echo "  clean        - Remove all build artifacts"
    echo "  check        - cargo check on every workspace member"
    echo "  test         - Run plain Rust tests (excludes pg_test suite)"
    echo "  pg-ext-test  - Run pgsleuth-pg-ext #[pg_test] suite via cargo pgrx test"
    echo ""
    echo "Options:"
    echo "  --backtrace, -b  Set RUST_BACKTRACE=1   (print call stack on errors)"
    echo "  --full           Set RUST_BACKTRACE=full (call stack + source snippets)"
    exit 1
    ;;
esac
