#!/usr/bin/env bash
# Contract for tools/check-noops.sh: each banned shape fails the guard, in
# each place it is looked for; messaged panics, expected panics and ordinary
# prose pass. Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

reset() {
    rm -rf "${work:?}"/*
    mkdir -p "$work/tools" "$work/crates/a/src" "$work/crates/a/tests" "$work/web/src" \
        "$work/crates/e6ircd/assets" "$work/crates/e6ircd/templates"
    cp "$root/tools/check-noops.sh" "$work/tools/"
    cat > "$work/crates/a/src/lib.rs" <<'RS'
pub fn f(x: Option<u8>) -> u8 {
    x.expect("the caller checked x")
}
#[test]
#[should_panic(expected = "the caller checked x")]
fn t() { f(None); }
RS
    printf '%s\n' 'fn t() { panic!("a test may panic loudly") }' > "$work/crates/a/tests/it.rs"
    printf '%s\n' 'export const todoList = [];' > "$work/web/src/main.js"
    printf '%s\n' '// the console script' > "$work/crates/e6ircd/assets/console.js"
    printf '%s\n' '<p>page</p>' > "$work/crates/e6ircd/templates/page.html"
}

expect_clean() { # REASON
    if ! (cd "$work" && tools/check-noops.sh) >/dev/null 2>&1; then
        echo "expected the no-op guard to pass: $1" >&2
        (cd "$work" && tools/check-noops.sh) >&2 || true
        exit 1
    fi
    reset
}

expect_fail() { # FILE REASON
    if out=$(cd "$work" && tools/check-noops.sh 2>&1); then
        echo "expected the no-op guard to fail: $2" >&2
        exit 1
    fi
    case "$out" in
        *"$1:"*) ;;
        *)
            echo "the no-op guard failed without naming $1: $2" >&2
            echo "$out" >&2
            exit 1
            ;;
    esac
    reset
}

reset
expect_clean 'baseline'

for line in 'fn g() { todo!() }' 'fn g() { unimplemented!("later") }' \
    'fn g() { panic!() }' 'fn g() { unreachable!("") }' 'fn g() { panic!( "" ) }' \
    'fn g(x: Option<u8>) -> u8 { x.expect("") }' '// TODO: handle this'; do
    printf '%s\n' "$line" >> "$work/crates/a/src/lib.rs"
    expect_fail crates/a/src/lib.rs "$line"
done

for file in web/src/main.js crates/e6ircd/assets/console.js crates/e6ircd/templates/page.html; do
    printf '%s\n' '// FIXME wire this up' >> "$work/$file"
    expect_fail "$file" "a marker in $file"
done

printf '%s\n' '#[test]' '#[should_panic]' 'fn any_panic() {}' >> "$work/crates/a/tests/it.rs"
expect_fail crates/a/tests/it.rs 'a bare #[should_panic] in an integration test'

echo "no-op guard contract ok"
