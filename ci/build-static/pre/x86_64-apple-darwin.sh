git clone --depth 1 --branch $BOTAN https://github.com/randombit/botan && \
cd botan
./configure.py --prefix=$PREFIX --without-documentation --without-openssl \
  --build-targets=static --minimized-build --enable-modules=$BOTAN_MODULES
sudo make -j2 install
cd ..

cat <<EOF >> .cargo/config
[target.$TARGET.botan-2]
rustc-link-search = ["native=$PREFIX/lib"]
rustc-link-lib = ["static=botan-2", "c++"]
EOF

