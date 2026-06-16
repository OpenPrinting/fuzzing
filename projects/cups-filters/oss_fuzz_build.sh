#!/bin/bash -eu

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export CFLAGS="$CFLAGS -fPIE"
export CXXFLAGS="$(echo "$CXXFLAGS" | sed 's/-stdlib=libc++//g') -fPIE"

FUZZER_DIR=$SRC/fuzzing/projects/cups-filters

# for libtool usage
export PATH=$PATH:$SRC/cups-filters
cp $FUZZER_DIR/fuzzer/patch_qpdf_xobject $SRC/cups-filters/filter/pdftopdf/

echo "OpenPrinting/fuzzing version: $(git -C $FUZZER_DIR rev-parse HEAD)"

# Build cups-filters
pushd $SRC/cups-filters
echo "cups-filters version: $(git rev-parse HEAD)"

# For multiple definition of `_cups_isalpha', `_cups_islower`, `_cups_toupper`
export LDFLAGS="${LDFLAGS:-} -Wl,--allow-multiple-definition"

### Temporal fix bug due to libqpdf-dev 9
pushd $SRC/cups-filters/filter/pdftopdf/
patch < patch_qpdf_xobject
popd

./autogen.sh
./configure --enable-static --disable-shared
make # -j$(nproc)

# Build the PDF-parsing fuzzer (C++) against the qpdf-backed pdftopdf processor
# objects produced above (minus the one that defines main()).
QPDF_CFLAGS=$(pkg-config --cflags libqpdf 2>/dev/null || true)
QPDF_LIBS=$(pkg-config --libs libqpdf 2>/dev/null || echo -lqpdf)
CUPS_LDLIBS=$(cups-config --libs 2>/dev/null || echo -lcups)
PDFTOPDF_OBJS=$(ls filter/pdftopdf/pdftopdf-*.o 2>/dev/null | grep -vE 'pdftopdf-pdftopdf\.o$')

$CXX $CXXFLAGS -std=c++17 $QPDF_CFLAGS -I filter/pdftopdf -I filter -I . \
    -c $FUZZER_DIR/fuzzer/fuzz_pdf.cc -o $WORK/fuzz_pdf.o
$CXX $CXXFLAGS $WORK/fuzz_pdf.o $PDFTOPDF_OBJS \
    .libs/libcupsfilters.a \
    $LIB_FUZZING_ENGINE $QPDF_LIBS $CUPS_LDLIBS \
    -Wl,--allow-multiple-definition \
    -o $OUT/fuzz_pdf

ldd $OUT/fuzz_pdf | awk '/=> \//{print $3}' | while read -r so; do
    b=$(basename "$so")
    case "$b" in
        libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|ld-linux*) continue ;;
    esac
    cp -L "$so" "$OUT/$b"
done
patchelf --force-rpath --set-rpath '$ORIGIN' $OUT/fuzz_pdf
popd

# Prepare corpus
pushd $FUZZER_DIR/seeds/
for seed_folder in *; do
    zip -r $seed_folder.zip $seed_folder
done
cp *.zip $OUT
popd
