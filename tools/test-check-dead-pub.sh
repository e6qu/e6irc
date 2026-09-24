#!/usr/bin/env bash
# Contract for tools/check-dead-pub.sh: a use from test-only code keeps
# nothing alive, and nothing a shipped path uses is flagged.
# Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/tools" "$work/crates/a/src/sub"
cp "$root/tools/check-dead-pub.sh" "$work/tools/"
src="$work/crates/a/src"

# A shipped baseline: `used` is referenced by shipped code, the char and raw
# string literals must neither open a string nor unbalance the brace matching,
# and `mod sub;` resolves to a file.
reset() {
    rm -rf "$src"
    mkdir -p "$src/sub"
    cat > "$src/lib.rs" <<'RS'
mod sub;
pub fn used() -> char { '"' }
pub fn caller() -> (char, &'static str) { (used(), r#"{ " }"#) }
pub fn braces() -> char { '{' }
fn main() { let _ = (caller(), braces(), sub::sub_caller()); }
RS
    printf '%s\n' 'pub fn in_sub() {}' 'pub fn sub_caller() { in_sub() }' > "$src/sub.rs"
}

run() { (cd "$work" && tools/check-dead-pub.sh) >/dev/null 2>&1; }

expect_clean() { # REASON
    if ! run; then
        echo "expected dead-pub guard to pass: $1" >&2
        (cd "$work" && tools/check-dead-pub.sh) >&2 || true
        exit 1
    fi
    reset
}

expect_fail() { # REASON
    if run; then
        echo "expected dead-pub guard failure: $1" >&2
        exit 1
    fi
    reset
}

reset
expect_clean 'baseline'

cat >> "$src/lib.rs" <<'RS'
pub fn only_tested() {}
#[cfg(test)]
mod tests {
    #[test]
    fn t() { super::only_tested(); let _ = '}'; }
}
RS
expect_fail 'pub fn used only by an inline #[cfg(test)] module'

cat >> "$src/lib.rs" <<'RS'
pub struct OnlyTested;
#[cfg(all(test, feature = "x"))]
fn helper() -> OnlyTested { OnlyTested }
RS
expect_fail 'pub item used only under cfg(all(test, ..))'

cat >> "$src/lib.rs" <<'RS'
pub fn only_in_test_file() {}
#[cfg(test)]
#[path = "sub/test_support.rs"]
mod test_support;
RS
printf '%s\n' 'fn t() { crate::only_in_test_file() }' > "$src/sub/test_support.rs"
expect_fail 'pub fn used only by a test-only `mod x;` file'

cat >> "$src/lib.rs" <<'RS'
pub fn used_under_any() {}
#[cfg(any(test, feature = "x"))]
fn shipped_too() { used_under_any() }
RS
expect_clean 'cfg(any(test, ..)) is shipped code'

cat >> "$src/lib.rs" <<'RS'
#[cfg(test)]
mod missing;
RS
expect_fail 'an unresolvable test-only `mod x;` fails loudly'

cat >> "$src/lib.rs" <<'RS'
// dead-pub-allow: exercised by the contract test
pub fn allowed() {}
RS
expect_clean 'dead-pub-allow marks an exception'

echo "dead-pub guard contract ok"
