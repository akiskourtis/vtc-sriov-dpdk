cmd_fm10k_common.o = gcc -Wp,-MD,./.fm10k_common.o.d.tmp -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ  -I/home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include -include /home/localadmin/dpdk-2.0.0/x86_64-native-linuxapp-gcc/include/rte_config.h -O3  -Wno-deprecated -Wno-unused-parameter -Wno-unused-value -Wno-strict-aliasing -Wno-format-extra-args -Wno-unused-variable -Wno-missing-field-initializers -Wno-unused-but-set-variable  -o fm10k_common.o -c /home/localadmin/dpdk-2.0.0/lib/librte_pmd_fm10k/base/fm10k_common.c 
