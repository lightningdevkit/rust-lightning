shopt -s extglob

rm -r target
cargo test
mkdir target/kcov target/kcov/unit target/kcov/integration target/kcov/merged
ls target
kcov --verify target/kcov/unit target/debug/lightning_invoice-!(*.d)
kcov --verify target/kcov/integration target/debug/ser_de-!(*.d)
kcov --include-pattern="$(pwd)/src" --merge target/kcov/merged target/kcov/unit target/kcov/integration
find . -type l | xargs -n 1 rm

git add -f target/kcov
git commit -m "last kcov result"
git push -f https://sgeisler:$GITHUB_TOKEN@github.com/rust-bitcoin/rust-lightning-invoice.git HEAD:gh-pages