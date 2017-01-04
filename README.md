# sriov-dpdk
A virtual Traffic Classifier VNF, on top of DPDK and SR-IOV

In order to install the VNF, with DPDK acceleration you need to first build the nDPI module.

```bash
cd ndpi
./autogen.sh
./configure
make
make install
```

then we need to go to DPDK build, with the usual way and run the l3fwd example

```bash
./build/l3fwd  -c 0x3 -n 2 -- -p 0x3 --config="(0,0,0),(1,0,1)"
```
