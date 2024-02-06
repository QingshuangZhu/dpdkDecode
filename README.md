# What is dpdkDecode?
dpdkDecode is decode tool based on DPDK. It only provides basic decoding for ftp and http protocols.
This application needs at least 6 logical cores to run:
* 1 lcore for packet distribution,
* 1 lcore for packet RX,
* 1 lcore for packet TX,
* 1 lcore for worker threads,
* 1 lcore for flow table age,
* 1 lcore for output information.

# How to run?
1. System Requirements
    * Python 3.6 or later.
    * Meson (version 0.53.2+) and ninja.

2. Compiling and Installing DPDK

```
meson setup build --prefix=/home/xxx/install/dpdk    #Configure the project, These options can be listed by running meson configure inside a configured build folder
cd build
ninja    #Build the project
meson install    #Install the project
ldconfig    #Update the binding and caching of dynamic linkers
```

3. Compiling and Runing dpdkDecode

```
export PKG_CONFIG_PATH=/home/xxx/install/dpdk/lib64/pkgconfig
export LD_LIBRARY_PATH=/home/xxx/install/dpdk/lib64:$LD_LIBRARY_PATH
make
./build/dpdkDecode -l 0-5 -- -p 0x1
```
