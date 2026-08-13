#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
BUILD="$HERE/.build"

GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
NC=$'\033[0m'

info() { echo "${GREEN}[INFO]${NC}  $*"; }
warn() { echo "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo "${RED}[FAIL]${NC}  $*"; exit 1; }
step() { echo; echo "=== $* ==="; }

case "$(uname -s)" in
  Linux)
    SHLIB=so
    LD_VAR=LD_LIBRARY_PATH
    SHARED_FLAG="-shared"
    ;;
  Darwin)
    SHLIB=dylib
    LD_VAR=DYLD_LIBRARY_PATH
    SHARED_FLAG="-dynamiclib"
    ;;
  *)
    die "unsupported OS: $(uname -s)"
    ;;
esac

JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"


python_has_mldsa() {
    "$1" -c 'import ssl,sys; sys.exit(0 if ssl.OPENSSL_VERSION_INFO[:2] >= (3,5) else 1)' \
        2>/dev/null
}

openssl_has_mldsa() {
    "$1" genpkey -algorithm mldsa65 -out /dev/null 2>/dev/null
}

select_toolchain() {
    step "1/6  Select a toolchain that supports ML-DSA"

    for tool in git cc make
    do
        command -v "$tool" >/dev/null \
            || die "missing '$tool'. On Ubuntu: sudo apt install build-essential git"
    done

    local candidate
    PYTHON="${PYTHON:-}"
    if [ -n "$PYTHON" ]
    then
        python_has_mldsa "$PYTHON" \
            || die "PYTHON=$PYTHON is linked against $("$PYTHON" -c 'import ssl;print(ssl.OPENSSL_VERSION)'), which has no ML-DSA"
    else
        for candidate in python3.14 python3.13 python3.12 python3.11 python3 \
                         /opt/homebrew/bin/python3 /usr/local/bin/python3
        do
            candidate="$(command -v "$candidate" 2>/dev/null || true)"
            [ -n "$candidate" ] || continue
            if python_has_mldsa "$candidate"
            then
                PYTHON="$candidate"
                break
            fi
        done
    fi
    [ -n "$PYTHON" ] || die "no Python found whose ssl module has ML-DSA (OpenSSL >= 3.5).
    macOS:  brew install python@3.13
    Ubuntu: use a Python built against OpenSSL >= 3.5, or a python.org build
    Then re-run, optionally as: PYTHON=/path/to/python3 ./setup.sh"

    OPENSSL="${OPENSSL:-}"
    if [ -n "$OPENSSL" ]
    then
        openssl_has_mldsa "$OPENSSL" || die "OPENSSL=$OPENSSL cannot generate ML-DSA keys"
    else
        for candidate in openssl /opt/homebrew/opt/openssl@3/bin/openssl \
                         /usr/local/opt/openssl@3/bin/openssl
        do
            candidate="$(command -v "$candidate" 2>/dev/null || true)"
            [ -n "$candidate" ] || continue
            if openssl_has_mldsa "$candidate"
            then
                OPENSSL="$candidate"
                break
            fi
        done
    fi
    [ -n "$OPENSSL" ] || die "no openssl found that supports ML-DSA-65 (needs >= 3.5).
    macOS:  brew install openssl@3
    Then re-run, optionally as: OPENSSL=/path/to/openssl ./setup.sh"

    OPENSSL_BIN_DIR="$(dirname "$OPENSSL")"
    OPENSSL_PREFIX="$(dirname "$OPENSSL_BIN_DIR")"

    info "python   $PYTHON  ($("$PYTHON" -c 'import sys;print(sys.version.split()[0])'), $("$PYTHON" -c 'import ssl;print(ssl.OPENSSL_VERSION)'))"
    info "openssl  $OPENSSL  ($("$OPENSSL" version | cut -d' ' -f1-2))"
    info "cc       $(cc --version 2>&1 | head -1)"
    info "cores    $JOBS"

    [ -f "$OPENSSL_PREFIX/include/openssl/opensslv.h" ] \
        || pkg-config --exists libcrypto 2>/dev/null \
        || [ -f /usr/include/openssl/opensslv.h ] \
        || die "OpenSSL development headers not found next to $OPENSSL.
    Ubuntu: sudo apt install libssl-dev
    macOS:  brew install openssl@3"
    info "libcrypto headers found"
}


create_venv() {
    step "2/6  Virtual environment"
    [ -d "$VENV" ] || "$PYTHON" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet cmake
    info "cmake $("$VENV/bin/cmake" --version | head -1 | awk '{print $3}')"
}


build_liboqs() {
    step "3/6  Build liboqs with stateful XMSS"
    mkdir -p "$BUILD"
    [ -d "$BUILD/liboqs" ] || git clone --depth 1 \
        https://github.com/open-quantum-safe/liboqs.git "$BUILD/liboqs"

    # The STFL and HAZARDOUS flags are mandatory. liboqs refuses XMSS key
    # generation and signing without them.
    rm -rf "$BUILD/liboqs/build"
    mkdir -p "$BUILD/liboqs/build"
    cd "$BUILD/liboqs/build"
    "$VENV/bin/cmake" .. -G "Unix Makefiles" \
        -DCMAKE_INSTALL_PREFIX="$VENV" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$(command -v cc)" \
        -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_ENABLE_SIG_STFL=ON \
        -DOQS_ENABLE_SIG_STFL_XMSS=ON \
        -DOQS_ENABLE_SIG_STFL_XMSSMT=ON \
        -DOQS_ENABLE_SIG_ML_DSA=ON \
        -DOQS_ALLOW_STFL_KEY_AND_SIG_GEN=ON \
        -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON > cmake.log 2>&1 \
        || { tail -30 cmake.log; die "liboqs cmake failed, see $PWD/cmake.log"; }

    info "configured, building with make -j$JOBS"
    make -j"$JOBS" > make.log 2>&1 \
        || { tail -30 make.log; die "liboqs build failed, see $PWD/make.log"; }
    make install > install.log 2>&1 \
        || { tail -20 install.log; die "liboqs install failed"; }

    cd "$HERE"
    OQS_LIB_DIR="$VENV/lib"
    [ -d "$VENV/lib64" ] && OQS_LIB_DIR="$VENV/lib64"
    ls "$OQS_LIB_DIR"/liboqs.* >/dev/null 2>&1 \
        || die "liboqs not found after install"
    info "liboqs installed into $OQS_LIB_DIR"
}


install_liboqs_python() {
    step "4/6  Install liboqs-python"
    [ -d "$BUILD/liboqs-python" ] || git clone --depth 1 \
        https://github.com/open-quantum-safe/liboqs-python.git \
        "$BUILD/liboqs-python"
    "$VENV/bin/pip" install --quiet "$BUILD/liboqs-python"
    info "liboqs-python installed"
}


compile_xmss_helper() {
    step "5/6  Compile the XMSS ctypes helper"
    cc $SHARED_FLAG -fPIC -O2 \
       -I"$VENV/include" \
       -L"$OQS_LIB_DIR" -Wl,-rpath,"$OQS_LIB_DIR" \
       -o "lib/libxmss_helper.$SHLIB" \
       lib/xmss_helper.c -loqs \
       || die "failed to compile lib/xmss_helper.c"

    # lib/crypto.py loads the .so name on every platform.
    [ "$SHLIB" = dylib ] && ln -sf libxmss_helper.dylib lib/libxmss_helper.so
    info "built lib/libxmss_helper.$SHLIB"
}


install_python_deps() {
    step "6/6  Python dependencies and activation script"
    "$VENV/bin/pip" install --quiet \
        autogen-agentchat "autogen-ext[openai]" openai pyyaml \
        matplotlib seaborn numpy requests
    info "installed runtime, benchmark and plotting dependencies"

    {
        echo "#!/usr/bin/env bash"
        echo "# Source this before running anything:  source activate.sh"
        echo "source \"$VENV/bin/activate\""
        echo "export PATH=\"$OPENSSL_BIN_DIR:\$PATH\""
        echo "export $LD_VAR=\"$OQS_LIB_DIR\${$LD_VAR:+:\$$LD_VAR}\""
        echo "echo \"magiQ environment ready (\$(python -V), \$(openssl version | cut -d' ' -f1-2)).\""
    } > "$HERE/activate.sh"
    chmod +x "$HERE/activate.sh"
    info "wrote activate.sh"

    if [ ! -f "$HERE/llm.yaml" ]
    then
        cp "$HERE/llm.example.yaml" "$HERE/llm.yaml"
        info "created llm.yaml from the example, edit it before running main.py"
    fi
}


verify() {
    step "Verify"
    export "$LD_VAR"="$OQS_LIB_DIR"
    export PATH="$OPENSSL_BIN_DIR:$PATH"
    "$VENV/bin/python" - <<'PY'
import ctypes
import os
import socket
import ssl
import subprocess
import tempfile
import threading

import oqs

path = os.path.join("lib", "libxmss_helper.so")
lib = ctypes.CDLL(path if os.path.exists(path) else path.replace(".so", ".dylib"))
lib.xmss_init()
for name in ("xmss_pk_length", "xmss_sig_length"):
    fn = getattr(lib, name)
    fn.argtypes = [ctypes.c_char_p]
    fn.restype = ctypes.c_size_t

for algo in (b"XMSS-SHA2_10_256", b"XMSS-SHA2_16_256"):
    pk, sig = lib.xmss_pk_length(algo), lib.xmss_sig_length(algo)
    assert pk and sig, f"{algo.decode()} unavailable"
    print(f"  {algo.decode():18} pk={pk}B sig={sig}B")

signer = oqs.Signature("ML-DSA-65")
pk = signer.generate_keypair()
print(f"  {'ML-DSA-65':18} pk={len(pk)}B sig={len(signer.sign(b'x'))}B")

# End-to-end proof that the transport this protocol needs actually works:
# mint ML-DSA-65 certificates and complete a mutually authenticated TLS 1.3
# handshake with them, which is what agent-to-agent sessions do.
with tempfile.TemporaryDirectory() as d:
    j = lambda n: os.path.join(d, n)
    run = lambda *a: subprocess.run(["openssl", *a], check=True,
                                    capture_output=True)
    run("genpkey", "-algorithm", "mldsa65", "-out", j("ca.key"))
    run("req", "-new", "-x509", "-key", j("ca.key"), "-out", j("ca.crt"),
        "-days", "1", "-subj", "/CN=verify-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for role, cn in (("server", "localhost"), ("client", "verify-client")):
        run("genpkey", "-algorithm", "mldsa65", "-out", j(f"{role}.key"))
        args = ["req", "-new", "-key", j(f"{role}.key"), "-out", j(f"{role}.csr"),
                "-subj", f"/CN={cn}"]
        if role == "server":
            args += ["-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"]
        run(*args)
        run("x509", "-req", "-in", j(f"{role}.csr"), "-CA", j("ca.crt"),
            "-CAkey", j("ca.key"), "-CAcreateserial", "-out", j(f"{role}.crt"),
            "-days", "1", "-copy_extensions", "copyall")

    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = sctx.maximum_version = ssl.TLSVersion.TLSv1_3
    sctx.load_cert_chain(j("server.crt"), j("server.key"))
    sctx.verify_mode = ssl.CERT_REQUIRED
    sctx.load_verify_locations(cafile=j("ca.crt"))

    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.minimum_version = cctx.maximum_version = ssl.TLSVersion.TLSv1_3
    cctx.load_verify_locations(cafile=j("ca.crt"))
    cctx.load_cert_chain(j("client.crt"), j("client.key"))

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    result = {}

    def serve():
        conn, _ = srv.accept()
        with sctx.wrap_socket(conn, server_side=True) as tls:
            result["cipher"] = tls.cipher()[0]
            result["peer"] = dict(x[0] for x in tls.getpeercert()["subject"])
            tls.sendall(b"ok")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    with cctx.wrap_socket(socket.create_connection(srv.getsockname()),
                          server_hostname="localhost") as tls:
        assert tls.recv(2) == b"ok"
    thread.join(timeout=10)

print(f"  {'PQ-mTLS':18} {result['cipher']}, "
      f"ML-DSA-65 client cert {result['peer']['commonName']!r} verified")
PY
}


select_toolchain
create_venv
build_liboqs
install_liboqs_python
compile_xmss_helper
install_python_deps
verify

echo
info "Setup complete. Next:"
echo
echo "    source activate.sh"
echo "    python main.py"
echo
