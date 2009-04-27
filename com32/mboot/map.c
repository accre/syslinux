/* ----------------------------------------------------------------------- *
 *
 *   Copyright 2007-2008 H. Peter Anvin - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author: H. Peter Anvin
 *
 *   Permission is hereby granted, free of charge, to any person
 *   obtaining a copy of this software and associated documentation
 *   files (the "Software"), to deal in the Software without
 *   restriction, including without limitation the rights to use,
 *   copy, modify, merge, publish, distribute, sublicense, and/or
 *   sell copies of the Software, and to permit persons to whom
 *   the Software is furnished to do so, subject to the following
 *   conditions:
 *
 *   The above copyright notice and this permission notice shall
 *   be included in all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *   OTHER DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------- */

/*
 * map.c
 *
 * Functions that deal with the memory map of various objects
 */

#include "mboot.h"

static struct syslinux_movelist *ml = NULL;
static struct syslinux_memmap *mmap = NULL, *amap = NULL;
static struct multiboot_header *mbh;
static addr_t mboot_high_water_mark = 0x100000;

/*
 * Note: although there is no such thing in the spec, at least Xen makes
 * assumptions as to where in the memory space Grub would have loaded
 * certain things.  To support that, if "high" is set, then allocate this
 * at an address strictly above any previous allocations.
 *
 * As a precaution, this also pads the data with zero up to the next
 * alignment datum.
 */
addr_t map_data(const void *data, size_t len, size_t align, int flags)
{
  addr_t start = (flags & MAP_HIGH) ? mboot_high_water_mark : 0x2000;
  addr_t pad   = (flags & MAP_NOPAD) ? 0 : -len & (align-1);
  addr_t xlen  = len+pad;

  if (syslinux_memmap_find(amap, SMT_FREE, &start, &xlen, align) ||
      syslinux_add_memmap(&amap, start, len+pad, SMT_ALLOC) ||
      syslinux_add_movelist(&ml, start, (addr_t)data, len) ||
      (pad && syslinux_add_memmap(&mmap, start+len, pad, SMT_ZERO))) {
    printf("Cannot map %zu bytes\n", len+pad);
    return 0;
  }

  dprintf("Mapping 0x%08x bytes (%#x pad) at 0x%08x\n", len, pad, start);

  if (start+len+pad > mboot_high_water_mark)
    mboot_high_water_mark = start+len+pad;

  return start;
}

addr_t map_string(const char *string)
{
  if (!string)
    return 0;
  else
    return map_data(string, strlen(string)+1, 1, 0);
}

int map_image(void *ptr, size_t len)
{
  int mbh_len;
  char *cptr = ptr;
  Elf32_Ehdr *eh = ptr;
  Elf32_Phdr *ph;
  Elf32_Shdr *sh;
  unsigned int i;
  uint32_t bad_flags;

  regs.eax = MULTIBOOT_VALID;

  /*
   * Search for the multiboot header...
   */
  mbh_len = 0;
  for (i = 0 ; i < MULTIBOOT_SEARCH ; i += 4) {
    mbh = (struct multiboot_header *)((char *)ptr + i);
    if (mbh->magic != MULTIBOOT_MAGIC)
      continue;
    if (mbh->magic + mbh->flags + mbh->checksum)
      continue;
    if (mbh->flags & MULTIBOOT_VIDEO_MODE)
      mbh_len = 48;
    else if (mbh->flags & MULTIBOOT_AOUT_KLUDGE)
      mbh_len = 32;
    else
      mbh_len = 12;

    if (i + mbh_len < len)
      mbh_len = 0;		/* Invalid... */
    else
      break;			/* Found something... */
  }

  if (mbh_len) {
    bad_flags = mbh->flags & (MULTIBOOT_UNSUPPORTED|MULTIBOOT_VIDEO_MODE);
    if (bad_flags) {
      printf("Unsupported Multiboot flags set: %#x\n", bad_flags);
      return -1;
    }
  }

  /*
   * Note: mmap is the memory map (containing free and zeroed regions)
   * needed by syslinux_shuffle_boot_pm(); amap is a map where we keep
   * track ourselves which target memory ranges have already been
   * allocated.
   */
  if ( len < sizeof(Elf32_Ehdr) ||
       memcmp(eh->e_ident, "\x7f""ELF\1\1\1", 6) ||
       (eh->e_machine != EM_386 && eh->e_machine != EM_486 &&
	eh->e_machine != EM_X86_64) ||
       eh->e_version != EV_CURRENT ||
       eh->e_ehsize < sizeof(Elf32_Ehdr) || eh->e_ehsize >= len ||
       eh->e_phentsize < sizeof(Elf32_Phdr) ||
       !eh->e_phnum ||
       eh->e_phoff+eh->e_phentsize*eh->e_phnum > len )
    eh = NULL;			/* No valid ELF header found */

  mmap = syslinux_memory_map();
  amap = syslinux_dup_memmap(mmap);
  if (!mmap || !amap) {
    error("Failed to allocate initial memory map!\n");
    goto bail;
  }

#if DEBUG
  dprintf("Initial memory map:\n");
  syslinux_dump_memmap(stdout, mmap);
#endif

  /*
   * Note: the Multiboot Specification implies that AOUT_KLUDGE should
   * have precedence over the ELF header.  However, Grub disagrees, and
   * Grub is "the reference bootloader" for the Multiboot Specification.
   * This is insane, since it makes the AOUT_KLUDGE bit functionally
   * useless, but at least Solaris apparently depends on this behavior.
   */
  if (eh) {
    regs.eip = eh->e_entry;

    ph = (Elf32_Phdr *)(cptr+eh->e_phoff);

    for (i = 0; i < eh->e_phnum; i++) {
      if (ph->p_type == PT_LOAD || ph->p_type == PT_PHDR) {
	/* This loads at p_paddr, which is arguably the correct semantics.
	   The SysV spec says that SysV loads at p_vaddr (and thus Linux does,
	   too); that is, however, a major brainfuckage in the spec. */
	addr_t addr  = ph->p_paddr;
	addr_t msize = ph->p_memsz;
	addr_t dsize = min(msize, ph->p_filesz);

	dprintf("Segment at 0x%08x data 0x%08x len 0x%08x\n",
		addr, dsize, msize);

	if (syslinux_memmap_type(amap, addr, msize) != SMT_FREE) {
	  printf("Memory segment at 0x%08x (len 0x%08x) is unavailable\n",
		 addr, msize);
	  goto bail;		/* Memory region unavailable */
	}

	/* Mark this region as allocated in the available map */
	if (syslinux_add_memmap(&amap, addr, msize, SMT_ALLOC)) {
	  error("Overlapping segments found in ELF header\n");
	  goto bail;
	}

	if (ph->p_filesz) {
	  /* Data present region.  Create a move entry for it. */
	  if (syslinux_add_movelist(&ml, addr, (addr_t)cptr+ph->p_offset,
				    dsize)) {
	    error("Failed to map PHDR data\n");
	    goto bail;
	  }
	}
	if (msize > dsize) {
	  /* Zero-filled region.  Mark as a zero region in the memory map. */
	  if (syslinux_add_memmap(&mmap, addr+dsize, msize-dsize, SMT_ZERO)) {
	    error("Failed to map PHDR zero region\n");
	    goto bail;
	  }
	}
	if (addr+msize > mboot_high_water_mark)
	  mboot_high_water_mark = addr+msize;
      } else {
	/* Ignore this program header */
      }

      ph = (Elf32_Phdr *)((char *)ph + eh->e_phentsize);
    }

    /* Load the ELF symbol table */
    if (eh->e_shoff) {
      addr_t addr, len;

      sh = (Elf32_Shdr *)((char *)eh + eh->e_shoff);

      len = eh->e_shentsize * eh->e_shnum;
      /*
       * Align this, but don't pad -- in general this means a bunch of
       * smaller sections gets packed into a single page.
       */
      addr = map_data(sh, len, 4096, MAP_HIGH|MAP_NOPAD);
      if (!addr) {
	error("Failed to map symbol table\n");
	goto bail;
      }

      mbinfo.flags |= MB_INFO_ELF_SHDR;
      mbinfo.syms.e.addr  = addr;
      mbinfo.syms.e.num   = eh->e_shnum;
      mbinfo.syms.e.size  = eh->e_shentsize;
      mbinfo.syms.e.shndx = eh->e_shstrndx;

      for (i = 0; i < eh->e_shnum; i++) {
	addr_t align;

	if (!sh[i].sh_size)
	  continue;		/* Empty section */
	if (sh[i].sh_flags & SHF_ALLOC)
	  continue;		/* SHF_ALLOC sections should have PHDRs */

	align = sh[i].sh_addralign ? sh[i].sh_addralign : 0;
	addr = map_data((char *)ptr + sh[i].sh_offset, sh[i].sh_size,
			align, MAP_HIGH);
	if (!addr) {
	  error("Failed to map symbol section\n");
	  goto bail;
	}
	sh[i].sh_addr = addr;
      }
    }
  } else if (mbh_len && (mbh->flags & MULTIBOOT_AOUT_KLUDGE)) {
    /*
     * a.out kludge thing...
     */
    char *data_ptr;
    addr_t data_len, bss_len;

    regs.eip = mbh->entry_addr;

    data_ptr = (char *)mbh - (mbh->header_addr - mbh->load_addr);
    data_len = mbh->load_end_addr - mbh->load_addr;
    bss_len  = mbh->bss_end_addr - mbh->load_end_addr;

    if (syslinux_memmap_type(amap, mbh->load_addr, data_len+bss_len)
	!= SMT_FREE) {
      printf("Memory segment at 0x%08x (len 0x%08x) is unavailable\n",
	     mbh->load_addr, data_len+bss_len);
      goto bail;		/* Memory region unavailable */
    }
    if (syslinux_add_memmap(&amap, mbh->load_addr,
			    data_len+bss_len, SMT_ALLOC)) {
      error("Failed to claim a.out address space!\n");
      goto bail;
    }
    if (data_len)
      if (syslinux_add_movelist(&ml, mbh->load_addr, (addr_t)data_ptr,
				data_len)) {
	error("Failed to map a.out data\n");
	goto bail;
      }
    if (bss_len)
      if (syslinux_add_memmap(&mmap, mbh->load_end_addr, bss_len, SMT_ZERO)) {
	error("Failed to map a.out bss\n");
	goto bail;
      }
    if (mbh->bss_end_addr > mboot_high_water_mark)
      mboot_high_water_mark = mbh->bss_end_addr;
  } else {
    error("Invalid Multiboot image: neither ELF header nor a.out kludge found\n");
    goto bail;
  }

  return 0;

 bail:
  syslinux_free_memmap(amap);
  syslinux_free_memmap(mmap);
  syslinux_free_movelist(ml);
  return -1;
}

/*
 * Set up a stack.  This isn't actually required by the spec, but it seems
 * like a prudent thing to do.  Also, put enough zeros at the top of the
 * stack that something that looks for an ELF invocation record will know
 * there isn't one.
 */
static void mboot_map_stack(void)
{
  addr_t start, len;

  if (syslinux_memmap_largest(amap, SMT_FREE, &start, &len) || len < 64)
    return;			/* Not much we can do, here... */

  regs.esp = (start+len-32) & ~7;
  dprintf("Mapping stack at 0x%08x\n", regs.esp);
  syslinux_add_memmap(&mmap, regs.esp, 32, SMT_ZERO);
}

void mboot_run(int bootflags)
{
  mboot_map_stack();
  
  dprintf("Running, eip = 0x%08x, ebx = 0x%08x\n", regs.eip, regs.ebx);

  syslinux_shuffle_boot_pm(ml, mmap, bootflags, &regs);
}