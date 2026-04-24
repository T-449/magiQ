#!/usr/bin/env bash
 
# setup.sh — Complete setup for MAGIQ 
#  
# Builds the full PQ crypto stack and installs all Python dependencies.
#   ./setup.sh            # conda env = magiq
#   ./setup.sh myenv      # custom env name
#
# After setup:
#   source activate.sh
#   python main.py


set -euo pipefail

# Clear any leftover PQ OpenSSL config — conda needs the default openssl.cnf
unset OPENSSL_CONF 2>/dev/null || true
unset OPENSSL_MODULES 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/_build"
ENV_NAME="${1:-magiq}"

LIBOQS_TAGS=("main" "0.12.0" "0.11.0" "0.10.1")
LIBOQS_USED_TAG=""

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
step() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

BUILD_OK=0

cleanup() {
    if [ "$BUILD_OK" -eq 0 ]; then
        echo ""
        echo -e "${RED}[CLEANUP]${NC} Build failed — removing partial artifacts ..."
        rm -rf "$BUILD_DIR"
        rm -f "$SCRIPT_DIR/lib/libxmss_helper.so" \
              "$SCRIPT_DIR/lib/libxmss_helper.dylib" \
              "$SCRIPT_DIR/openssl_pq.cnf" \
              "$SCRIPT_DIR/activate.sh"
        echo -e "${RED}[CLEANUP]${NC} Done. Fix the error above and re-run ./setup.sh"
    fi
}
trap cleanup EXIT


step "1/8  Locate conda"


CONDA_BASE=""
if command -v conda &>/dev/null; then
    CONDA_BASE="$(conda info --base 2>/dev/null)"
elif [ -d "$HOME/miniconda3" ]; then CONDA_BASE="$HOME/miniconda3"
elif [ -d "$HOME/anaconda3" ];  then CONDA_BASE="$HOME/anaconda3"
elif [ -d "$HOME/miniforge3" ]; then CONDA_BASE="$HOME/miniforge3"
fi

[ -z "$CONDA_BASE" ] && fail "conda not found. Install miniconda first:
    https://docs.conda.io/en/latest/miniconda.html"

# shellcheck source=/dev/null
source "$CONDA_BASE/etc/profile.d/conda.sh"
info "conda found at $CONDA_BASE"


step "2/8  Create conda environment '$ENV_NAME'"


if conda env list | grep -qw "$ENV_NAME"; then
    info "Environment '$ENV_NAME' already exists — reusing"
else
    info "Creating environment '$ENV_NAME' ..."
    conda create -n "$ENV_NAME" python=3.11 -y -q
fi

conda activate "$ENV_NAME"
info "Activated: $CONDA_PREFIX"

info "Installing build dependencies ..."
conda install -c conda-forge -y -q \
    cmake \
    compilers \
    openssl \
    git \
    pkg-config \
    make

CC_PATH="${CC:-$(which gcc 2>/dev/null || which cc 2>/dev/null || true)}"
CXX_PATH="${CXX:-$(which g++ 2>/dev/null || which c++ 2>/dev/null || true)}"
[ -z "$CC_PATH" ] && fail "No C compiler found after conda install"
info "C compiler: $CC_PATH"
info "OpenSSL: $(openssl version)"


step "3/8  Build liboqs"


mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
rm -rf liboqs liboqs-python

for TAG in "${LIBOQS_TAGS[@]}"; do
    info "Trying liboqs $TAG ..."
    if [ "$TAG" = "main" ]; then
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git \
            && LIBOQS_USED_TAG="main" && break
    else
        git clone --depth 1 --branch "$TAG" \
            https://github.com/open-quantum-safe/liboqs.git 2>/dev/null \
            && LIBOQS_USED_TAG="$TAG" && break
    fi
    warn "Tag $TAG not found, trying next ..."
done
[ -d "liboqs" ] || fail "Could not clone liboqs"

cd liboqs && mkdir -p build && cd build

cmake .. \
    -DCMAKE_INSTALL_PREFIX="$CONDA_PREFIX" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_ENABLE_SIG_STFL=ON \
    -DOQS_ENABLE_SIG_STFL_XMSS=ON \
    -DOQS_ENABLE_SIG_STFL_XMSSMT=ON \
    -DOQS_ENABLE_SIG_STFL_LMS=ON \
    -DOQS_ENABLE_SIG_ML_DSA=ON \
    -DOQS_ALLOW_STFL_KEY_AND_SIG_GEN=ON \
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON \
    ${CC_PATH:+-DCMAKE_C_COMPILER="$CC_PATH"} \
    ${CXX_PATH:+-DCMAKE_CXX_COMPILER="$CXX_PATH"} \
    2>&1 | grep -iE "XMSS|STFL|SIG_ML|ENABLE|ALLOW|HAZARD|not found|error" || true

make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)" 2>&1 | tail -3
make install 2>&1 | tail -1

OQS_LIB=""
for p in "$CONDA_PREFIX/lib/liboqs.so" "$CONDA_PREFIX/lib/liboqs.dylib" \
         "$CONDA_PREFIX/lib64/liboqs.so"; do
    [ -f "$p" ] && OQS_LIB="$p" && break
done
[ -z "$OQS_LIB" ] && fail "liboqs not found after install"
OQS_LIB_DIR="$(dirname "$OQS_LIB")"
info "liboqs installed: $OQS_LIB"


step "4/8  Install liboqs-python"


cd "$BUILD_DIR"
info "Cloning liboqs-python (matching liboqs: ${LIBOQS_USED_TAG:-main}) ..."
if [ -n "$LIBOQS_USED_TAG" ] && [ "$LIBOQS_USED_TAG" != "main" ]; then
    git clone --depth 1 --branch "$LIBOQS_USED_TAG" \
        https://github.com/open-quantum-safe/liboqs-python.git 2>/dev/null \
    || git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
else
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
fi

cd liboqs-python
pip install . -q || fail "pip install liboqs-python failed"

python -c "
import oqs
s = oqs.Signature('ML-DSA-65')
pk = s.generate_keypair()
sig = s.sign(b'test')
v = oqs.Signature('ML-DSA-65')
v.verify(b'test', sig, pk)
print(f'  ML-DSA-65 sign+verify OK (pk={len(pk)}B)')
" || fail "ML-DSA-65 test failed"
info "liboqs-python OK"


step "5/8  Build oqs-provider for PQ TLS"


cd "$BUILD_DIR"
rm -rf oqs-provider
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git \
    || fail "Could not clone oqs-provider"

cd oqs-provider && mkdir -p _build && cd _build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$CONDA_PREFIX" \
    -DOPENSSL_ROOT_DIR="$CONDA_PREFIX" \
    -Dliboqs_DIR="$CONDA_PREFIX/lib/cmake/liboqs" \
    ${CC_PATH:+-DCMAKE_C_COMPILER="$CC_PATH"} \
    || fail "oqs-provider cmake failed"

make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)" \
    || fail "oqs-provider build failed"

make install || fail "oqs-provider install failed"

OQS_MOD_DIR=""
for d in "$CONDA_PREFIX/lib/ossl-modules" "$CONDA_PREFIX/lib64/ossl-modules"; do
    [ -d "$d" ] && OQS_MOD_DIR="$d" && break
done
if [ -z "$OQS_MOD_DIR" ]; then
    OQS_MOD_DIR="$(find "$CONDA_PREFIX" -name 'oqsprovider.*' -type f 2>/dev/null \
                   | head -1 | xargs dirname 2>/dev/null || true)"
fi
[ -z "$OQS_MOD_DIR" ] && fail "oqs-provider module not found after install"
info "oqs-provider module dir: $OQS_MOD_DIR"

export OPENSSL_MODULES="$OQS_MOD_DIR"
if openssl genpkey -provider oqsprovider -provider default \
     -algorithm mldsa65 -out /dev/null 2>/dev/null; then
    info "ML-DSA-65 available in openssl ✓"
elif openssl genpkey -algorithm mldsa65 -out /dev/null 2>/dev/null; then
    info "ML-DSA-65 available in openssl (native) ✓"
else
    fail "ML-DSA-65 not available in openssl after oqs-provider install.
    Check: OPENSSL_MODULES=$OQS_MOD_DIR"
fi


step "6/8  Compile XMSS C helper"


cd "$SCRIPT_DIR"

case "$(uname -s)" in
    Darwin*) SHLIB_EXT="dylib"; SHARED_FLAG="-dynamiclib" ;;
    *)       SHLIB_EXT="so";    SHARED_FLAG="-shared" ;;
esac

"$CC_PATH" $SHARED_FLAG -fPIC -O2 \
    -I"$CONDA_PREFIX/include" \
    -L"$OQS_LIB_DIR" \
    -Wl,-rpath,"$OQS_LIB_DIR" \
    -o "lib/libxmss_helper.$SHLIB_EXT" \
    lib/xmss_helper.c \
    -loqs

if [ "$SHLIB_EXT" = "dylib" ] && [ ! -f lib/libxmss_helper.so ]; then
    ln -sf "libxmss_helper.dylib" lib/libxmss_helper.so
fi

[ -f lib/libxmss_helper.so ] || [ -f "lib/libxmss_helper.$SHLIB_EXT" ] \
    || fail "libxmss_helper not built"
info "libxmss_helper compiled"

info "Verifying XMSS-SHA2_10_256 support ..."
python -c "
import ctypes, sys, os
lib_path = os.path.join('lib', 'libxmss_helper.so')
if not os.path.exists(lib_path):
    lib_path = os.path.join('lib', 'libxmss_helper.$SHLIB_EXT')
lib = ctypes.CDLL(lib_path)
lib.xmss_init()
lib.xmss_pk_length.argtypes = [ctypes.c_char_p]
lib.xmss_pk_length.restype  = ctypes.c_size_t
lib.xmss_sig_length.argtypes = [ctypes.c_char_p]
lib.xmss_sig_length.restype  = ctypes.c_size_t
pk_len  = lib.xmss_pk_length(b'XMSS-SHA2_10_256')
sig_len = lib.xmss_sig_length(b'XMSS-SHA2_10_256')
if pk_len == 0 or sig_len == 0:
    print(f'  XMSS-SHA2_10_256: pk_len={pk_len}, sig_len={sig_len}')
    sys.exit(1)
print(f'  XMSS-SHA2_10_256: pk={pk_len}B, sig={sig_len}B ✓')
" || fail "XMSS-SHA2_10_256 not available — check cmake output for XMSS/STFL flags."


step "7/8  Generate OpenSSL config and activation script"


OQS_PROV_LIB="$(find "$OQS_MOD_DIR" -name 'oqsprovider*' -type f | head -1)"
[ -z "$OQS_PROV_LIB" ] && fail "oqsprovider shared library not found in $OQS_MOD_DIR"

cat > "$SCRIPT_DIR/openssl_pq.cnf" << OSSL_EOF
# Auto-generated by setup.sh — do not edit manually, re-run setup.sh to regenerate
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = $OQS_PROV_LIB
OSSL_EOF

info "openssl_pq.cnf written"

OPENSSL_CONF="$SCRIPT_DIR/openssl_pq.cnf" OPENSSL_MODULES="$OQS_MOD_DIR" \
    openssl genpkey -algorithm mldsa65 -out /dev/null 2>/dev/null \
    || fail "ML-DSA-65 not working with generated openssl_pq.cnf"
info "ML-DSA-65 verified with openssl_pq.cnf ✓"

cat > "$SCRIPT_DIR/activate.sh" << ACTIVATE_EOF
#!/usr/bin/env bash
# Source this before running the demo:  source activate.sh
source "$CONDA_BASE/etc/profile.d/conda.sh"
conda activate $ENV_NAME
export OPENSSL_MODULES="$OQS_MOD_DIR"
export OPENSSL_CONF="$SCRIPT_DIR/openssl_pq.cnf"
echo "Environment '$ENV_NAME' activated."
echo "  OPENSSL_MODULES=\$OPENSSL_MODULES"
echo "  OPENSSL_CONF=\$OPENSSL_CONF"
ACTIVATE_EOF
chmod +x "$SCRIPT_DIR/activate.sh"
info "activate.sh written"


step "8/8  Install Python runtime dependencies"


info "Installing autogen-agentchat, openai, pyyaml ..."
pip install -q autogen-agentchat openai pyyaml
info "Python dependencies installed"

python -c "
import autogen_agentchat, openai, yaml, oqs
print('  autogen-agentchat:', autogen_agentchat.__version__)
print('  openai:           ', openai.__version__)
print('  oqs available     : yes')
" || fail "Dependency smoke-test failed — see errors above"


BUILD_OK=1
echo ""
info "============================================"
info "  Setup complete!"
info "============================================"
echo ""
echo "  Edit llm.yaml to set your LLM endpoint and API key, then:"
echo ""
echo "    source activate.sh"
echo "    python main.py"
echo ""
echo "  Algorithm summary:"
echo "    XMSS:    $(python -c "import json; print(json.load(open('config.json'))['algorithms']['xmss'])" 2>/dev/null || echo '?')"
echo "    ML-DSA:  $(python -c "import json; print(json.load(open('config.json'))['algorithms']['mldsa'])" 2>/dev/null || echo '?')"
echo "    KEX:     $(python -c "import json; print(json.load(open('config.json'))['algorithms']['kex'])"  2>/dev/null || echo '?')"
echo ""
