#!/bin/bash
set -uex

python3 --version
opt --version

if [ -z ${SIDEROPHILE_DIR+x} ]; then
    TEMP=$(mktemp -d -t)
    SIDEROPHILE_DIR="$TEMP/siderophile"
    git clone -b taylor-patches https://github.com/defuse/siderophile/ "$TEMP/siderophile"
    cd "$SIDEROPHILE_DIR"
    git rev-parse HEAD
    ./setup.sh
    cd -
fi

for crate in "$@"
do
    cd $crate
    rm -rf siderophile_out
    # Find the last-installed version of LLVM.
    # From https://raw.githubusercontent.com/include-what-you-use/include-what-you-use/master/.travis.yml
    VERSION=`ls -t /usr/lib/ | grep '^llvm-' | head -n 1 | sed -E 's/llvm-(.+)/\1/'`
    export PATH="$(llvm-config-$VERSION --bindir):$PATH"
    # TODO: We probably want an arbitrary map between directory / crate names.
    crate_underscore=$(echo "$crate" | tr "-" "_" | sed 's/librustzcash/rustzcash/')
    "$SIDEROPHILE_DIR/analyze.sh" $crate_underscore > /dev/null
    cd ..
done

set +x

for crate in "$@"
do
    cd $crate

    CRATE_ARTIFACTS="../ci/artifacts/$crate/siderophile"
    mkdir -p "$CRATE_ARTIFACTS"
    cp siderophile_out/nodes_to_taint.txt "$CRATE_ARTIFACTS/nodes_to_taint.txt"
    cp siderophile_out/badness.txt "$CRATE_ARTIFACTS/badness.txt"

    echo "CRATE: $crate"
    echo "Nodes to taint:"
    cat siderophile_out/nodes_to_taint.txt | sed 's/^/    /'
    echo "Badness:"
    cat siderophile_out/badness.txt | sed 's/^/    /'
    cd ..
done
