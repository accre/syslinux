/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2006 Erwan Velu - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdio.h>
#include <string.h>
#include "cpuid.h"

struct cpu_dev * cpu_devs[X86_VENDOR_NUM] = {};

/*
* CPUID functions returning a single datum
*/
static inline unsigned int cpuid_eax(unsigned int op)
{
        unsigned int eax;

        __asm__("cpuid"
                : "=a" (eax)
                : "0" (op)
                : "bx", "cx", "dx");
        return eax;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
        unsigned int eax, ecx;

        __asm__("cpuid"
                : "=a" (eax), "=c" (ecx)
                : "0" (op)
                : "bx", "dx" );
        return ecx;
}
static inline unsigned int cpuid_edx(unsigned int op)
{
        unsigned int eax, edx;

        __asm__("cpuid"
                : "=a" (eax), "=d" (edx)
                : "0" (op)
                : "bx", "cx");
        return edx;
}

/* Standard macro to see if a specific flag is changeable */
static inline int flag_is_changeable_p(u32 flag)
{
        u32 f1, f2;

        asm("pushfl\n\t"
            "pushfl\n\t"
            "popl %0\n\t"
            "movl %0,%1\n\t"
            "xorl %2,%0\n\t"
            "pushl %0\n\t"
            "popfl\n\t"
            "pushfl\n\t"
            "popl %0\n\t"
            "popfl\n\t"
            : "=&r" (f1), "=&r" (f2)
            : "ir" (flag));

        return ((f1^f2) & flag) != 0;
}

/* Probe for the CPUID instruction */
static int have_cpuid_p(void)
{
        return flag_is_changeable_p(X86_EFLAGS_ID);
}

static struct cpu_dev amd_cpu_dev = {
        .c_vendor       = "AMD",
        .c_ident        = { "AuthenticAMD" }
};

static struct cpu_dev intel_cpu_dev = {
        .c_vendor       = "Intel",
        .c_ident        = { "GenuineIntel" }
};

static struct cpu_dev cyrix_cpu_dev = {
        .c_vendor       = "Cyrix",
        .c_ident        = { "CyrixInstead" }
};

static struct cpu_dev umc_cpu_dev = {
        .c_vendor       = "UMC",
	.c_ident        = { "UMC UMC UMC" }

};

static struct cpu_dev nexgen_cpu_dev = {
        .c_vendor       = "Nexgen",
        .c_ident        = { "NexGenDriven" }
};

static struct cpu_dev centaur_cpu_dev = {
        .c_vendor       = "Centaur",
        .c_ident        = { "CentaurHauls" }
};

static struct cpu_dev rise_cpu_dev = {
        .c_vendor       = "Rise",
        .c_ident        = { "RiseRiseRise" }
};

static struct cpu_dev transmeta_cpu_dev = {
        .c_vendor       = "Transmeta",
        .c_ident        = { "GenuineTMx86", "TransmetaCPU" }
};

void init_cpu_devs(void)
{
	cpu_devs[X86_VENDOR_INTEL] = &intel_cpu_dev;
	cpu_devs[X86_VENDOR_CYRIX] = &cyrix_cpu_dev;
	cpu_devs[X86_VENDOR_AMD] = &amd_cpu_dev;
	cpu_devs[X86_VENDOR_UMC] = &umc_cpu_dev;
	cpu_devs[X86_VENDOR_NEXGEN] = &nexgen_cpu_dev;
	cpu_devs[X86_VENDOR_CENTAUR] = &centaur_cpu_dev;
	cpu_devs[X86_VENDOR_RISE] = &rise_cpu_dev;
	cpu_devs[X86_VENDOR_TRANSMETA] = &transmeta_cpu_dev;
}

void get_cpu_vendor(struct cpuinfo_x86 *c)
{
        char *v = c->x86_vendor_id;
        int i;
	init_cpu_devs();
        for (i = 0; i < X86_VENDOR_NUM; i++) {
                if (cpu_devs[i]) {
                        if (!strcmp(v,cpu_devs[i]->c_ident[0]) ||
                            (cpu_devs[i]->c_ident[1] &&
                             !strcmp(v,cpu_devs[i]->c_ident[1]))) {
                                c->x86_vendor = i;
                                return;
                        }
                }
        }

        c->x86_vendor = X86_VENDOR_UNKNOWN;
}

int get_model_name(struct cpuinfo_x86 *c)
{
        unsigned int *v;
        char *p, *q;

        if (cpuid_eax(0x80000000) < 0x80000004)
                return 0;

        v = (unsigned int *) c->x86_model_id;
        cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
        cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
        cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
        c->x86_model_id[48] = 0;

        /* Intel chips right-justify this string for some dumb reason;
           undo that brain damage */
        p = q = &c->x86_model_id[0];
        while ( *p == ' ' )
             p++;
        if ( p != q ) {
             while ( *p )
                  *q++ = *p++;
             while ( q <= &c->x86_model_id[48] )
                  *q++ = '\0';  /* Zero-pad the rest */
        }

        return 1;
}

void generic_identify(struct cpuinfo_x86 *c)
{
        u32 tfms, xlvl;
        int junk;
	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
              (int *)&c->x86_vendor_id[0],
              (int *)&c->x86_vendor_id[8],
              (int *)&c->x86_vendor_id[4]);

        get_cpu_vendor(c);
        /* Intel-defined flags: level 0x00000001 */
        if ( c->cpuid_level >= 0x00000001 ) {
		u32 capability, excap;
                cpuid(0x00000001, &tfms, &junk, &excap, &capability);
                c->x86_capability[0] = capability;
                c->x86_capability[4] = excap;
                c->x86 = (tfms >> 8) & 15;
                c->x86_model = (tfms >> 4) & 15;
                if (c->x86 == 0xf) {
                        c->x86 += (tfms >> 20) & 0xff;
                        c->x86_model += ((tfms >> 16) & 0xF) << 4;
                }
                c->x86_mask = tfms & 15;
		if (capability & (1<<19))
                        c->x86_cache_alignment = ((junk >> 8) & 0xff) * 8;
              } else {
                      /* Have CPUID level 0 only - unheard of */
                      c->x86 = 4;
	}

        /* AMD-defined flags: level 0x80000001 */
        xlvl = cpuid_eax(0x80000000);
        if ( (xlvl & 0xffff0000) == 0x80000000 ) {
               if ( xlvl >= 0x80000001 ) {
                     c->x86_capability[1] = cpuid_edx(0x80000001);
                     c->x86_capability[6] = cpuid_ecx(0x80000001);
               }
               if ( xlvl >= 0x80000004 )
                     get_model_name(c); /* Default name */
       }
}

/*
 * Checksum an MP configuration block.
 */

static int mpf_checksum(unsigned char *mp, int len)
{
        int sum = 0;

        while (len--)
                sum += *mp++;

        return sum & 0xFF;
}

static int smp_scan_config (unsigned long base, unsigned long length)
{
        unsigned long *bp = base;
        struct intel_mp_floating *mpf;

//        printf("Scan SMP from %p for %ld bytes.\n", bp,length);
        if (sizeof(*mpf) != 16) {
                printf("Error: MPF size\n");
		return 0;
	}

        while (length > 0) {
                mpf = (struct intel_mp_floating *)bp;
                if ((*bp == SMP_MAGIC_IDENT) &&
                        (mpf->mpf_length == 1) &&
                        !mpf_checksum((unsigned char *)bp, 16) &&
                        ((mpf->mpf_specification == 1)
                                || (mpf->mpf_specification == 4)) ) {
                        return 1;
                }
                bp += 4;
                length -= 16;
        }
        return 0;
}

int find_smp_config (void)
{
//        unsigned int address;

        /*
         * FIXME: Linux assumes you have 640K of base ram..
         * this continues the error...
         *
         * 1) Scan the bottom 1K for a signature
         * 2) Scan the top 1K of base RAM
         * 3) Scan the 64K of bios
         */
        if (smp_scan_config(0x0,0x400) ||
                smp_scan_config(639*0x400,0x400) ||
                        smp_scan_config(0xF0000,0x10000))
                return 1;
        /*
         * If it is an SMP machine we should know now, unless the
         * configuration is in an EISA/MCA bus machine with an
         * extended bios data area.
         *
         * there is a real-mode segmented pointer pointing to the
         * 4K EBDA area at 0x40E, calculate and scan it here.
         *
         * NOTE! There are Linux loaders that will corrupt the EBDA
         * area, and as such this kind of SMP config may be less
         * trustworthy, simply because the SMP table may have been
         * stomped on during early boot. These loaders are buggy and
         * should be fixed.
         *
         * MP1.4 SPEC states to only scan first 1K of 4K EBDA.
         */

//        address = get_bios_ebda();
//        if (address)
//                smp_scan_config(address, 0x400);
	 return 0;
}


void set_cpu_flags(struct cpuinfo_x86 *c, s_cpu *cpu) {
cpu->flags.fpu=cpu_has(c, X86_FEATURE_FPU);
cpu->flags.vme=cpu_has(c, X86_FEATURE_VME);
cpu->flags.de=cpu_has(c, X86_FEATURE_DE);
cpu->flags.pse=cpu_has(c, X86_FEATURE_PSE);
cpu->flags.tsc=cpu_has(c, X86_FEATURE_TSC);
cpu->flags.msr=cpu_has(c, X86_FEATURE_MSR);
cpu->flags.pae=cpu_has(c, X86_FEATURE_PAE);
cpu->flags.mce=cpu_has(c, X86_FEATURE_MCE);
cpu->flags.cx8=cpu_has(c, X86_FEATURE_CX8);
cpu->flags.apic=cpu_has(c, X86_FEATURE_APIC);
cpu->flags.sep=cpu_has(c, X86_FEATURE_SEP);
cpu->flags.mtrr=cpu_has(c, X86_FEATURE_MTRR);
cpu->flags.pge=cpu_has(c, X86_FEATURE_PGE);
cpu->flags.mca=cpu_has(c, X86_FEATURE_MCA);
cpu->flags.cmov=cpu_has(c, X86_FEATURE_CMOV);
cpu->flags.pat=cpu_has(c, X86_FEATURE_PAT);
cpu->flags.pse_36=cpu_has(c, X86_FEATURE_PSE36);
cpu->flags.psn=cpu_has(c, X86_FEATURE_PN);
cpu->flags.clflsh=cpu_has(c, X86_FEATURE_CLFLSH);
cpu->flags.dts=cpu_has(c, X86_FEATURE_DTES);
cpu->flags.acpi=cpu_has(c, X86_FEATURE_ACPI);
cpu->flags.mmx=cpu_has(c, X86_FEATURE_MMX);
cpu->flags.fxsr=cpu_has(c, X86_FEATURE_FXSR);
cpu->flags.sse=cpu_has(c, X86_FEATURE_XMM);
cpu->flags.sse2=cpu_has(c, X86_FEATURE_XMM2);
cpu->flags.ss=cpu_has(c, X86_FEATURE_SELFSNOOP);
cpu->flags.htt=cpu_has(c, X86_FEATURE_HT);
cpu->flags.acc=cpu_has(c, X86_FEATURE_ACC);
cpu->flags.syscall=cpu_has(c, X86_FEATURE_SYSCALL);
cpu->flags.mp=cpu_has(c, X86_FEATURE_MP);
cpu->flags.nx=cpu_has(c, X86_FEATURE_NX);
cpu->flags.mmxext=cpu_has(c, X86_FEATURE_MMXEXT);
cpu->flags.lm=cpu_has(c, X86_FEATURE_LM);
cpu->flags.nowext=cpu_has(c, X86_FEATURE_3DNOWEXT);
cpu->flags.now=cpu_has(c, X86_FEATURE_3DNOW);
cpu->flags.smp = find_smp_config();
}

void set_generic_info(struct cpuinfo_x86 *c,s_cpu *cpu) {
	cpu->family=c->x86;
	cpu->vendor_id=c->x86_vendor;
	cpu->model_id=c->x86_model;
	cpu->stepping=c->x86_mask;
	strncpy(cpu->vendor,cpu_devs[c->x86_vendor]->c_vendor,CPU_VENDOR_SIZE);
	strncpy(cpu->model,c->x86_model_id,CPU_MODEL_SIZE);
}

void detect_cpu(s_cpu *cpu)
{
         struct cpuinfo_x86 c;
	 c.x86_cache_alignment = 32;
         c.x86_cache_size = -1;
         c.x86_vendor = X86_VENDOR_UNKNOWN;
         c.cpuid_level = -1;    /* CPUID not detected */
         c.x86_model = c.x86_mask = 0; /* So far unknown... */
         c.x86_vendor_id[0] = '\0'; /* Unset */
         c.x86_model_id[0] = '\0';  /* Unset */
	 memset(&c.x86_vendor_id,'\0',CPU_VENDOR_SIZE);

         if (!have_cpuid_p())
                 return;

	generic_identify(&c);
	set_generic_info(&c,cpu);
	set_cpu_flags(&c,cpu);
}