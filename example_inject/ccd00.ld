OUTPUT_ARCH(arm)

PHDRS {
   seg_text    PT_LOAD                 FLAGS(0x01 | 0x04);
   seg_rodata  PT_LOAD                 FLAGS(0x04);
   seg_data    PT_LOAD                 FLAGS(0x02 | 0x04);
   seg_bss     PT_LOAD                 FLAGS(0x02 | 0x04);
   seg_cro     PT_LOAD                 FLAGS(0x01 | 0x04);
   seg_linking PT_LOAD                 FLAGS(0x04);
}

SECTIONS
{
   . = 0x180;
	.text : ALIGN(0x4) {
		build/crt0.o(.init)
		*(.text)
		*(.plt)
	} : seg_text
	
	.got ALIGN(32) : { *(.got*) }  : seg_text
	
	.rodata : ALIGN(0x4) {
		*(.rodata)
	} : seg_rodata
	
	.rel.dyn ALIGN(32) : { *(.rel.dyn*) } : seg_linking
   .rel.plt ALIGN(32) : { *(.rel.plt*) } : seg_linking
   .dynsym ALIGN(32) : { *(.dynsym*) } : seg_linking
   .dynstr ALIGN(32) : { *(.dynstr*) } : seg_linking
   .dynamic ALIGN(32) : { *(.dynamic*) } : seg_linking
   .hash ALIGN(32) : { *(.hash*) } : seg_linking
	
	.data : ALIGN(0x4) {
		*(.data)
	} : seg_data
	
	.bss : ALIGN(0x4) {
		*(.bss)
	} : seg_bss
	
	
}

