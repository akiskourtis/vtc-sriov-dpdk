cmd_eal_common_tailqs.o = gcc -Wp,-MD,./.eal_common_tailqs.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ  -I/home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include -include /home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include/rte_config.h -I/home/localadmin/dpdk-2.0.0/lib/librte_eal/linuxapp/eal/include -I/home/localadmin/dpdk-2.0.0/lib/librte_eal/common -I/home/localadmin/dpdk-2.0.0/lib/librte_eal/common/include -I/home/localadmin/dpdk-2.0.0/lib/librte_ring -I/home/localadmin/dpdk-2.0.0/lib/librte_mempool -I/home/localadmin/dpdk-2.0.0/lib/librte_malloc -I/home/localadmin/dpdk-2.0.0/lib/librte_ether -I/home/localadmin/dpdk-2.0.0/lib/librte_ivshmem -I/home/localadmin/dpdk-2.0.0/lib/librte_pmd_ring -I/home/localadmin/dpdk-2.0.0/lib/librte_pmd_pcap -I/home/localadmin/dpdk-2.0.0/lib/librte_pmd_af_packet -I/home/localadmin/dpdk-2.0.0/lib/librte_pmd_xenvirt  -O3   -o eal_common_tailqs.o -c /home/localadmin/dpdk-2.0.0/lib/librte_eal/common/eal_common_tailqs.c 
