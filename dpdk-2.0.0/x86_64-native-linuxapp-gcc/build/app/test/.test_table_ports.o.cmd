cmd_test_table_ports.o = gcc -Wp,-MD,./.test_table_ports.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ  -I/home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include -include /home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include/rte_config.h -O3  -D_GNU_SOURCE   -o test_table_ports.o -c /home/localadmin/dpdk-2.0.0/app/test/test_table_ports.c 
