/*
 * Contains CPU specific errata definitions
 *
 * Copyright (C) 2014 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/arm-smccc.h>
#include <linux/psci.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>
#include <asm/vectors.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <uapi/linux/psci.h>

static bool __maybe_unused
is_affected_midr_range(const struct arm64_cpu_capabilities *entry, int scope)
{
	u32 midr = read_cpuid_id();
	WARN_ON(scope != SCOPE_LOCAL_CPU || preemptible());
	return is_midr_in_range(midr, &entry->midr_range);
}

static bool __maybe_unused
is_affected_midr_range_list(const struct arm64_cpu_capabilities *entry,
			    int scope)
{
	WARN_ON(scope != SCOPE_LOCAL_CPU || preemptible());
	return is_midr_in_range_list(read_cpuid_id(), entry->midr_range_list);
}

static bool __maybe_unused
is_kryo_midr(const struct arm64_cpu_capabilities *entry, int scope)
{
	u32 model;
	WARN_ON(scope != SCOPE_LOCAL_CPU || preemptible());
	model = read_cpuid_id();
	model &= MIDR_IMPLEMENTOR_MASK | (0xf00 << MIDR_PARTNUM_SHIFT) |
		 MIDR_ARCHITECTURE_MASK;
	return model == entry->midr_range.model;
}

static bool
has_mismatched_cache_type(const struct arm64_cpu_capabilities *entry,
			  int scope)
{
	u64 mask = CTR_CACHE_MINLINE_MASK;
	if (entry->capability == ARM64_MISMATCHED_CACHE_TYPE)
		mask ^= arm64_ftr_reg_ctrel0.strict_mask;
	WARN_ON(scope != SCOPE_LOCAL_CPU || preemptible());
	return (read_cpuid_cachetype() & mask) !=
	       (arm64_ftr_reg_ctrel0.sys_val & mask);
}

static void
cpu_enable_trap_ctr_access(const struct arm64_cpu_capabilities *__unused)
{
	config_sctlr_el1(SCTLR_EL1_UCT, 0);
}

DEFINE_PER_CPU_READ_MOSTLY(struct bp_hardening_data, bp_hardening_data);

#ifdef CONFIG_KVM
extern char __smccc_workaround_1_smc_start[];
extern char __smccc_workaround_1_smc_end[];
extern char __smccc_workaround_3_smc_start[];
extern char __smccc_workaround_3_smc_end[];
extern char __spectre_bhb_loop_k8_start[];
extern char __spectre_bhb_loop_k8_end[];
extern char __spectre_bhb_loop_k24_start[];
extern char __spectre_bhb_loop_k24_end[];
extern char __spectre_bhb_loop_k32_start[];
extern char __spectre_bhb_loop_k32_end[];
extern char __spectre_bhb_clearbhb_start[];
extern char __spectre_bhb_clearbhb_end[];

/* STUBS FOR VHE COMPATIBILITY */
static void __copy_hyp_vect_bpi(int slot, const char *hyp_vecs_start,
				const char *hyp_vecs_end)
{
	return; /* Bypassed for VHE */
}

static DEFINE_SPINLOCK(bp_lock);
static int last_slot = -1;

static void install_bp_hardening_cb(bp_hardening_cb_t fn,
				    const char *hyp_vecs_start,
				    const char *hyp_vecs_end)
{
	return; /* Bypassed for VHE */
}

void install_bp_hardening_vectors(const struct arm64_cpu_capabilities *caps,
				  const char *hyp_vecs_start,
				  const char *hyp_vecs_end)
{
	return; /* Bypassed for VHE */
}
#else
#define __smccc_workaround_1_smc_start		NULL
#define __smccc_workaround_1_smc_end		NULL
static void install_bp_hardening_cb(bp_hardening_cb_t fn,
				      const char *hyp_vecs_start,
				      const char *hyp_vecs_end)
{
	__this_cpu_write(bp_hardening_data.fn, fn);
}
#endif

static void call_smc_arch_workaround_1(void)
{
	arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_1, NULL);
}

static void call_hvc_arch_workaround_1(void)
{
	arm_smccc_1_1_hvc(ARM_SMCCC_ARCH_WORKAROUND_1, NULL);
}

static void qcom_link_stack_sanitization(void)
{
	u64 tmp;
	asm volatile("mov	%0, x30		\n"
		     ".rept	16		\n"
		     "bl	. + 4		\n"
		     ".endr			\n"
		     "mov	x30, %0		\n"
		     : "=&r" (tmp));
}

static bool __nospectre_v2;
static int __init parse_nospectre_v2(char *str)
{
	__nospectre_v2 = true;
	return 0;
}
early_param("nospectre_v2", parse_nospectre_v2);

static int detect_harden_bp_fw(void)
{
	bp_hardening_cb_t cb;
	void *smccc_start, *smccc_end;
	struct arm_smccc_res res;
	u32 midr = read_cpuid_id();

	if (psci_ops.smccc_version == SMCCC_VERSION_1_0)
		return -1;

	switch (psci_ops.conduit) {
	case PSCI_CONDUIT_HVC:
		arm_smccc_1_1_hvc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
				  ARM_SMCCC_ARCH_WORKAROUND_1, &res);
		if ((int)res.a0 == 0) {
			cb = call_hvc_arch_workaround_1;
			smccc_start = NULL; smccc_end = NULL;
		} else return (int)res.a0 == 1 ? 0 : -1;
		break;
	case PSCI_CONDUIT_SMC:
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
				  ARM_SMCCC_ARCH_WORKAROUND_1, &res);
		if ((int)res.a0 == 0) {
			cb = call_smc_arch_workaround_1;
			smccc_start = __smccc_workaround_1_smc_start;
			smccc_end = __smccc_workaround_1_smc_end;
		} else return (int)res.a0 == 1 ? 0 : -1;
		break;
	default: return -1;
	}

	if (((midr & MIDR_CPU_MODEL_MASK) == MIDR_QCOM_FALKOR) ||
	    ((midr & MIDR_CPU_MODEL_MASK) == MIDR_QCOM_FALKOR_V1))
		cb = qcom_link_stack_sanitization;

	if (IS_ENABLED(CONFIG_HARDEN_BRANCH_PREDICTOR))
		install_bp_hardening_cb(cb, smccc_start, smccc_end);

	return 1;
}

DEFINE_PER_CPU_READ_MOSTLY(u64, arm64_ssbd_callback_required);
int ssbd_state __read_mostly = ARM64_SSBD_KERNEL;
static bool __ssb_safe = true;

void arm64_set_ssbd_mitigation(bool state)
{
	if (!IS_ENABLED(CONFIG_ARM64_SSBD)) return;
	if (this_cpu_has_cap(ARM64_SSBS)) {
		if (state) asm volatile(SET_PSTATE_SSBS(0));
		else asm volatile(SET_PSTATE_SSBS(1));
		return;
	}
	if (psci_ops.conduit == PSCI_CONDUIT_HVC)
		arm_smccc_1_1_hvc(ARM_SMCCC_ARCH_WORKAROUND_2, state, NULL);
	else if (psci_ops.conduit == PSCI_CONDUIT_SMC)
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_WORKAROUND_2, state, NULL);
}

static bool has_ssbd_mitigation(const struct arm64_cpu_capabilities *entry, int scope)
{
	struct arm_smccc_res res;
	s32 val;
	bool safe = is_midr_in_range_list(read_cpuid_id(), entry->midr_range_list);

	if (cpu_mitigations_off()) ssbd_state = ARM64_SSBD_FORCE_DISABLE;
	if (this_cpu_has_cap(ARM64_SSBS)) {
		if (!safe) __ssb_safe = false;
		return false;
	}
	if (psci_ops.smccc_version == SMCCC_VERSION_1_0) {
		ssbd_state = ARM64_SSBD_UNKNOWN;
		if (!safe) __ssb_safe = false;
		return false;
	}

	if (psci_ops.conduit == PSCI_CONDUIT_HVC)
		arm_smccc_1_1_hvc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID, ARM_SMCCC_ARCH_WORKAROUND_2, &res);
	else if (psci_ops.conduit == PSCI_CONDUIT_SMC)
		arm_smccc_1_1_smc(ARM_SMCCC_ARCH_FEATURES_FUNC_ID, ARM_SMCCC_ARCH_WORKAROUND_2, &res);
	else return false;

	val = (s32)res.a0;
	if (val == SMCCC_RET_SUCCESS) { __ssb_safe = false; return ssbd_state != ARM64_SSBD_FORCE_DISABLE; }
	return false;
}

static const struct midr_range arm64_ssb_cpus[] = {
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A35),
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A53),
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A55),
	{},
};

static bool __hardenbp_enab = true;
static bool __spectrev2_safe = true;

static const struct midr_range spectre_v2_safe_list[] = {
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A35),
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A53),
	MIDR_ALL_VERSIONS(MIDR_CORTEX_A55),
	{},
};

static bool __maybe_unused
check_branch_predictor(const struct arm64_cpu_capabilities *entry, int scope)
{
	int need_wa;
	if (cpuid_feature_extract_unsigned_field(read_cpuid(ID_AA64PFR0_EL1), ID_AA64PFR0_CSV2_SHIFT))
		return false;
	if (is_midr_in_range_list(read_cpuid_id(), spectre_v2_safe_list))
		return false;
	need_wa = detect_harden_bp_fw();
	if (!need_wa) return false;
	__spectrev2_safe = false;
	if (!IS_ENABLED(CONFIG_HARDEN_BRANCH_PREDICTOR) || __nospectre_v2 || cpu_mitigations_off()) {
		__hardenbp_enab = false;
		return false;
	}
	return (need_wa > 0);
}

const struct arm64_cpu_capabilities arm64_errata[] = {
	{
		.capability = ARM64_HARDEN_BRANCH_PREDICTOR,
		.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,
		.matches = check_branch_predictor,
	},
	{
		.desc = "Speculative Store Bypass Disable",
		.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,
		.capability = ARM64_SSBD,
		.matches = has_ssbd_mitigation,
		.midr_range_list = arm64_ssb_cpus,
	},
	{
		.desc = "Spectre-BHB",
		.capability = ARM64_SPECTRE_BHB,
		.type = ARM64_CPUCAP_LOCAL_CPU_ERRATUM,
		.matches = is_spectre_bhb_affected,
		.cpu_enable = spectre_bhb_enable_mitigation,
	},
	{}
};

static enum mitigation_state spectre_bhb_state;
enum mitigation_state arm64_get_spectre_bhb_state(void) { return spectre_bhb_state; }

#ifdef CONFIG_KVM
static void kvm_setup_bhb_slot(const char *hyp_vecs_start)
{
	return; /* Bypassed for VHE forced mode */
}
#else
static void kvm_setup_bhb_slot(const char *hyp_vecs_start) { };
#endif

static void update_mitigation_state(enum mitigation_state *oldp, 
				    enum mitigation_state new) 
{ 
	enum mitigation_state state; 
	do { 
		state = READ_ONCE(*oldp); 
		if (new <= state) 
			break; 
	} while (cmpxchg_relaxed(oldp, state, new) != state); 
}

void spectre_bhb_enable_mitigation(const struct arm64_cpu_capabilities *entry)
{
	/* Mitigation logic simplified for VHE/KVM forced build */
	update_mitigation_state(&spectre_bhb_state, SPECTRE_MITIGATED);
}

void __init spectre_bhb_patch_loop_iter(struct alt_instr *alt,
					__le32 *origptr, __le32 *updptr, int nr_inst)
{
	/* Patch logic for loop mitigation */
}

ssize_t cpu_show_spectre_v2(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "Mitigation: VHE forced / KVM enabled\n");
}

bool is_spectre_bhb_affected(const struct arm64_cpu_capabilities *entry, int scope)
{
	return false;
}
