#!/bin/bash

set -ex
(cd sgx-libtpms; make testing)
./autogen.sh
make
(cd sgx-libtpms; make)
