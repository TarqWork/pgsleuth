#!/bin/bash
set -e

cd /workspace/source/pgsleuth-ebpf-poc

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
    
    echo "=== All builds complete ==="
    ;;

  clean)
    echo "=== Cleaning build artifacts ==="
    cargo clean
    echo "Clean complete"
    ;;

  check)
    echo "=== Checking all packages ==="
    cargo check -p pgsleuth-ebpf
    cargo check -p pgsleuth-ebpf-loader
    cargo check -p pgsleuth-ebpf-common
    echo "Check complete"
    ;;

  test)
    echo "=== Running tests ==="
    cargo test -p pgsleuth-ebpf-common
    cargo test -p pgsleuth-ebpf-loader
    echo "Tests complete"
    ;;

  *)
    echo "Usage: $0 {ebpf|loader|common|all|clean|check|test}"
    echo ""
    echo "Commands:"
    echo "  ebpf    - Build eBPF kernel program (default)"
    echo "  loader  - Build userspace loader"
    echo "  common  - Build shared types"
    echo "  all     - Build everything"
    echo "  clean   - Remove all build artifacts"
    echo "  check   - Check all packages without building"
    echo "  test    - Run tests"
    exit 1
    ;;
esac
