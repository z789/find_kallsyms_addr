
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/livepatch.h>
#include <linux/version.h>

static const char * const kallsyms_lookup_name_symbol = "kallsyms_lookup_name";
static unsigned long (*p_kallsyms_lookup_name)(const char *name) = NULL;

static int p_kallsyms_lookup_name_set(const char *val, const struct kernel_param *kp)
{
        unsigned long n;
        int ret;

        if (!val)
                return -EINVAL;

        ret = kstrtoul(val, 16, &n);
        if (ret < 0)
                return ret;

	p_kallsyms_lookup_name = (unsigned long (*)(const char *name))n;
	return 0;
}

static int p_kallsyms_lookup_name_get(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE, "%p\n", p_kallsyms_lookup_name);
}

static const struct kernel_param_ops p_kallsyms_lookup_name_ops = {
        .set = p_kallsyms_lookup_name_set,
        .get = p_kallsyms_lookup_name_get,
};

module_param_cb(kallsyms_lookup_name_addr, &p_kallsyms_lookup_name_ops, &p_kallsyms_lookup_name, 0444);
MODULE_PARM_DESC(kallsyms_lookup_name_addr, "Symbol kallsyms_lookup_name addr");


/*
 No export the func <kallsyms_lookup_name> from v5.7.1
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 1)
unsigned long find_kallsyms_addr(const char *name)
{
	unsigned long addr = 0;
	if (!p_kallsyms_lookup_name)
		p_kallsyms_lookup_name = (unsigned long (*)(const char *name))kallsyms_lookup_name;

	if (p_kallsyms_lookup_name) 
		addr = p_kallsyms_lookup_name(name);
	return addr;
}
#else

#ifdef CONFIG_KGDB_KDB
/* Symbol table format returned by kallsyms. */
typedef struct __ksymtab {
	unsigned long value;    /* Address of symbol */
	const char *mod_name;   /* Module containing symbol or
				 * "kernel" */
	unsigned long mod_start;
	unsigned long mod_end;
	const char *sec_name;   /* Section containing symbol */
	unsigned long sec_start;
	unsigned long sec_end;
	const char *sym_name;   /* Full symbol name, including
				 * any version */
	unsigned long sym_start;
	unsigned long sym_end;
} kdb_symtab_t;

int kdbgetsymval(const char *symname, kdb_symtab_t *symtab);
#endif

#ifdef CONFIG_KPROBES
static int __kprobes pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void __kprobes post_handler(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
	return;
}

static unsigned long find_addr_kprobe(const char *name)
{
	struct kprobe kp;
	unsigned long addr = 0;
	if (!name)
		goto end;

	kp.symbol_name = name;
	kp.offset = 0;
	kp.addr = 0;
	kp.pre_handler = pre_handler;
	kp.post_handler = post_handler;
	if (register_kprobe(&kp) == 0)
		unregister_kprobe(&kp);
	addr = (unsigned long) kp.addr;

end:
	return addr;
}
#endif

#ifdef CONFIG_LIVEPATCH
static int pre_patch(struct klp_object *obj)
{
	/*Must return -1*/
        return -1;
}

/*
 * Only stub function
 */
static unsigned long new_kallsyms_lookup_name(const char *name)
{
        return 0;
}

static struct klp_func symbol[] = {
        {
                .old_name = kallsyms_lookup_name_symbol,
                .new_func = new_kallsyms_lookup_name,
        }, { }
};

static struct klp_object objs[] = {
        {
                .funcs = symbol,
                .callbacks.pre_patch = pre_patch,
        }, { }
};

static struct klp_patch patch = {
        .mod = THIS_MODULE,
        .objs = objs,
};

static unsigned long find_addr_livepatch(const char *name, void *new_func)
{
	unsigned long addr = 0;
	int ret = -1;

	if (!name)
		goto end;
	symbol[0].old_name = name;
	symbol[0].old_func = 0;
	symbol[0].new_func = new_func;

	ret = klp_enable_patch(&patch); //ret < 0;
	addr = (unsigned long)symbol[0].old_func;
end:
	return addr;
}
MODULE_INFO(livepatch, "Y");
#endif

unsigned long find_kallsyms_addr(const char *name)
{
#ifdef CONFIG_KGDB_KDB
        kdb_symtab_t symtab; 
#endif
        unsigned long addr = 0;
        if (!name)
                goto end;

	if (!p_kallsyms_lookup_name) { 
#ifdef CONFIG_KGDB_KDB
		if (kdbgetsymval(kallsyms_lookup_name_symbol, &symtab)) {
			p_kallsyms_lookup_name = (unsigned long (*)(const char *name))symtab.sym_start;
		} else {
#endif
			p_kallsyms_lookup_name = (unsigned long (*)(const char *name))
						__symbol_get(kallsyms_lookup_name_symbol);
#ifdef CONFIG_KPROBES
			if (!p_kallsyms_lookup_name )
				p_kallsyms_lookup_name = (unsigned long (*)(const char *name))
							find_addr_kprobe(kallsyms_lookup_name_symbol);
#endif
#ifdef CONFIG_LIVEPATCH
			if (!p_kallsyms_lookup_name )
				p_kallsyms_lookup_name = (unsigned long (*)(const char *name))
							find_addr_livepatch(kallsyms_lookup_name_symbol,
										new_kallsyms_lookup_name);
#endif
#ifdef CONFIG_KGDB_KDB
		}
#endif 
	}

	if (p_kallsyms_lookup_name) 
		addr = p_kallsyms_lookup_name(name);
end:
        return addr;
}
#endif
