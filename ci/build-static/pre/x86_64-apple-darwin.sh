git clone --depth 1 --branch "$BOTAN_VERSION" https://github.com/randombit/botan && \
cd botan
./configure.py --prefix=$PREFIX --without-documentation --without-openssl \
  --build-targets=static --minimized-build --enable-modules=$BOTAN_MODULES
sudo make -j2 install
cd ..

cat <<EOF >> .cargo/config
[target.$TARGET.botan-3]
rustc-link-search = ["native=$PREFIX/lib"]
rustc-link-lib = ["static=botan-3", "c++"]
EOF

