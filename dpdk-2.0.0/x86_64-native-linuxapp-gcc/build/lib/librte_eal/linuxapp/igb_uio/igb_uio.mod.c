#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x1e94b2a0, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x62a79a6c, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0xcab94ac6, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0xdb62a73a, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xf62d5a7a, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0x3416aa48, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0xa26eac7, __VMLINUX_SYMBOL_STR(dev_notice) },
	{ 0xa898a1f, __VMLINUX_SYMBOL_STR(pci_intx_mask_supported) },
	{ 0xf2fd845d, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0x328c3420, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0xc2558d70, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0xa11b55b2, __VMLINUX_SYMBOL_STR(xen_start_info) },
	{ 0x731dba7a, __VMLINUX_SYMBOL_STR(xen_domain_type) },
	{ 0xc352b929, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0xee77a31a, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0x18561088, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x1c59e233, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0x2f700627, __VMLINUX_SYMBOL_STR(pci_request_regions) },
	{ 0x6a2abddc, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0x3d1f7a21, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xda22cdde, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x1e8d8f23, __VMLINUX_SYMBOL_STR(pci_check_and_mask_intx) },
	{ 0x27112c5d, __VMLINUX_SYMBOL_STR(pci_intx) },
	{ 0x2c8e7b52, __VMLINUX_SYMBOL_STR(pci_cfg_access_unlock) },
	{ 0x25bcd1e5, __VMLINUX_SYMBOL_STR(pci_cfg_access_lock) },
	{ 0x119d1d5, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x5944d015, __VMLINUX_SYMBOL_STR(__cachemode2pte_tbl) },
	{ 0xf1ce5bc0, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xd04d7f07, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x223c0dce, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0x8d499e8f, __VMLINUX_SYMBOL_STR(pci_release_regions) },
	{ 0x92a590f0, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x870850a0, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x47d988bf, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0xd4b438ab, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0xba5d82bb, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0x3c80c06c, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "1615B72D1C74E5105B464A1");
