# horses/include

Include path for the C/C++ harness side. Empty by design today: the M1/M2
harnesses are self-contained (`m1_harness.c`, `m2_hybrid.c`, `m2_memdiff.c`
define their own interfaces; funchook's headers come from
`horses/third_party/funchook/include`, passed by `build_m2.sh`).

This directory is the drop-in place for shared headers the moment several
harnesses need one (e.g. a common `horse_abi.h` for FR-6's hybrid contract).
`build_horse.sh` already passes `-I` here.
