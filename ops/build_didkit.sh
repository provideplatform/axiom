#!/bin/bash

rm -rf ./.didkit
mkdir ./.didkit
pushd ./.didkit
git clone https://github.com/spruceid/didkit
pushd ./didkit
git clone https://github.com/spruceid/didkit-go lib/didkit-go
git clone https://github.com/spruceid/ssi ../ssi --recurse-submodules
cargo build
mv ./target ../
popd
rm ./didkit/lib/didkit-go/didkit.h
cp ./target/didkit.h ./didkit/lib/didkit-go/
popd
