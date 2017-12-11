#include <cstdlib>

#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"
#include "cro.h"

using namespace ELFIO;

int main(int argc, char **argv)
{
   if (argc < 3)
   {
      printf("Usage: %s <input.cro> <output.elf>\n", argv[0]);
      return -1;
   }
   
   FILE* cro_file = fopen(argv[1], "rb");
   if (!cro_file)
   {
      printf("Failed to open file %s! Exiting...\n", argv[1]);
      return -1;
   }
   
   fseek(cro_file, 0, SEEK_END);
   uint32_t cro_size = ftell(cro_file);
   void* cro_data = malloc(cro_size);
   
   fseek(cro_file, 0, SEEK_SET);
   fread(cro_data, sizeof(uint8_t), cro_size, cro_file);
   fclose(cro_file);
   
   CRO_Header* cro_header = (CRO_Header*)cro_data;
   printf("Loaded CRO %s\n", cro_header->get_name(cro_data));
   
   elfio elf;
   elf.create(ELFCLASS32, ELFDATA2LSB);
   elf.set_os_abi(ELFOSABI_NONE);
	elf.set_type(ET_DYN);
	elf.set_machine(EM_ARM);
	elf.set_entry(cro_header->offs_text);
	
	CRO_Segment* cro_segments = cro_header->get_segments(cro_data);
	segment* segments[5];
	section* sections[5];
	for (int i = 0; i < cro_header->num_segments; i++)
	{
	   segment* seg = elf.segments.add();
	   printf("Segment %u: offs %x, size %x, type %x\n", i, cro_segments[i].offset, cro_segments[i].size, cro_segments[i].type);
	   
	   if (cro_segments[i].type == SEG_TEXT)
	   {
	      seg->set_type(PT_LOAD);
		   seg->set_flags(PF_R | PF_X);
		   
		   seg->set_align(0x10);
	   }
	   else if (cro_segments[i].type == SEG_RODATA)
	   {
	      seg->set_type(PT_LOAD);
		   seg->set_flags(PF_R);
		   
		   seg->set_align(0x4);
	   }
	   else if (cro_segments[i].type == SEG_DATA)
	   {
	      seg->set_type(PT_LOAD);
		   seg->set_flags(PF_R | PF_W);
		   
		   seg->set_align(0x1000);
	   }
	   else if (cro_segments[i].type == SEG_BSS)
	   {
	      seg->set_type(PT_LOAD);
		   seg->set_flags(PF_R | PF_W);
		   
		   seg->set_align(0x4);
		   
		   seg->set_virtual_address(cro_header->offs_data + cro_header->size_data);
	      seg->set_physical_address(cro_header->offs_data + cro_header->size_data);
	   }
	   
	   if (cro_segments[i].type != SEG_BSS)
	   {
	      seg->set_virtual_address(cro_segments[i].offset);
	      seg->set_physical_address(cro_segments[i].offset);
	   }
	   seg->set_memory_size(cro_segments[i].size);
	   seg->set_file_size(cro_segments[i].size);
	   
	   section* sec;
	   if (cro_segments[i].type == SEG_TEXT && cro_segments[i].offset == 0)
	   {
	      sec = elf.sections.add(".cro_info");

	      sec->set_type(SHT_PROGBITS);
	      sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
	   }
	   else if (cro_segments[i].type == SEG_TEXT)
	   {
	      sec = elf.sections.add(".text");
	      sec->set_type(SHT_PROGBITS);
	      sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
	   }
	   else if (cro_segments[i].type == SEG_RODATA)
	   {
	      sec = elf.sections.add(".rodata");
	      sec->set_type(SHT_PROGBITS);
	      sec->set_flags(SHF_ALLOC);
	   }
	   else if (cro_segments[i].type == SEG_DATA)
	   {
	      sec = elf.sections.add(".data");
	      sec->set_type(SHT_PROGBITS);
	      sec->set_flags(SHF_ALLOC | SHF_WRITE);
	   }
	   else if (cro_segments[i].type == SEG_BSS)
	   {
	      sec = elf.sections.add(".bss");
	      sec->set_type(SHT_NOBITS);
	      sec->set_flags(SHF_ALLOC | SHF_WRITE);
	      
	      sec->set_address(cro_header->offs_data + cro_header->size_data);
	   }
	   else
	   {
	      sec = elf.sections.add(".unk");
	      sec->set_type(SHT_NULL);
	   }
	   
	   if (cro_segments[i].type != SEG_BSS)
	      sec->set_address(cro_segments[i].offset);
	   sec->set_addr_align(4);
	   sec->set_data((char*)cro_data + cro_segments[i].offset, cro_segments[i].size);
      seg->add_section_index(sec->get_index(), sec->get_addr_align());
	   
	   sections[i] = sec;
	   segments[i] = seg;
	}

	section* strtab_sec = elf.sections.add(".dynstr");
	{
		strtab_sec->set_type(SHT_STRTAB);
		strtab_sec->set_flags(SHF_ALLOC);

		strtab_sec->set_overlay(sections[SEG_TEXT]->get_index());
		strtab_sec->set_addr_align(1);
	}
	string_section_accessor stra(strtab_sec);

	section* dynsym_sec = elf.sections.add(".dynsym");
	{
		dynsym_sec->set_type(SHT_DYNSYM);
		dynsym_sec->set_flags(SHF_ALLOC);
		dynsym_sec->set_entry_size(elf.get_default_entry_size(SHT_SYMTAB));

		dynsym_sec->set_link(strtab_sec->get_index());
		dynsym_sec->set_overlay(sections[SEG_TEXT]->get_index());
		dynsym_sec->set_addr_align(4);
	}
   symbol_section_accessor symd(elf, dynsym_sec);
   
   for (int i = 0; i < 5; i++)
   {
      symd.add_symbol(0, segments[i]->get_virtual_address(), 0, STB_LOCAL, STT_SECTION, 0, sections[i]->get_index());
   }
   
   section* text_rel_sec = elf.sections.add(".rela.text");
	text_rel_sec->set_type(SHT_RELA);
	text_rel_sec->set_entry_size(elf.get_default_entry_size(SHT_RELA));
	text_rel_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
	text_rel_sec->set_info(sections[SEG_TEXT]->get_index());
   text_rel_sec->set_overlay(sections[SEG_TEXT]->get_index());
   text_rel_sec->set_link(dynsym_sec->get_index());
   text_rel_sec->set_addr_align(4);
	relocation_section_accessor relt(elf, text_rel_sec);
	
   section* rodata_rel_sec = elf.sections.add(".rela.rodata");
	rodata_rel_sec->set_type(SHT_RELA);
	rodata_rel_sec->set_entry_size(elf.get_default_entry_size(SHT_RELA));
	rodata_rel_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
	rodata_rel_sec->set_info(sections[SEG_RODATA]->get_index());
   rodata_rel_sec->set_overlay(sections[SEG_RODATA]->get_index());
   rodata_rel_sec->set_link(dynsym_sec->get_index());
   rodata_rel_sec->set_addr_align(4);
	relocation_section_accessor relr(elf, rodata_rel_sec);
	
	section* data_rel_sec = elf.sections.add(".rela.data");
	data_rel_sec->set_type(SHT_RELA);
	data_rel_sec->set_entry_size(elf.get_default_entry_size(SHT_RELA));
	data_rel_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
	data_rel_sec->set_info(sections[SEG_DATA]->get_index());
   data_rel_sec->set_overlay(sections[SEG_DATA]->get_index());
   data_rel_sec->set_link(dynsym_sec->get_index());
   data_rel_sec->set_addr_align(4);
	relocation_section_accessor reld(elf, data_rel_sec);
	
	relocation_section_accessor* rel_accessors[3];
	rel_accessors[SEG_TEXT] = &relt;
	rel_accessors[SEG_RODATA] = &relr;
	rel_accessors[SEG_DATA] = &reld;
   
   for (int i = 0; i < cro_header->num_symbol_exports; i++)
   {
      CRO_Symbol* symbol = cro_header->get_export(cro_data, i);
      int seg_idx = symbol->seg_offset & 0xf;
      int seg_offs = symbol->seg_offset >> 4;
      printf("%x - %x %x\n", symbol->seg_offset, seg_idx, seg_offs);
      
      symd.add_symbol(stra, (char*)cro_data + symbol->offs_name, segments[seg_idx]->get_virtual_address() + seg_offs, 0, STB_GLOBAL, STT_NOTYPE, 0, sections[seg_idx]->get_index());
   }
	
	for (int i = 0; i < cro_header->num_symbol_imports; i++)
   {
      CRO_Symbol* symbol = cro_header->get_import(cro_data, i);
      uint32_t patch_offs = symbol->seg_offset;
      
      int index = symd.add_symbol(stra, (char*)cro_data + symbol->offs_name, 0x0, 0, STB_GLOBAL, STT_NOTYPE, 0, 0);
      
      if (!patch_offs) continue;
      
      CRO_Relocation* reloc = (CRO_Relocation*)((char*)cro_data + patch_offs);
      while(1)
      {
         int rel_seg_idx = reloc->seg_offset & 0xf;
         int rel_seg_offs = reloc->seg_offset >> 4;
         
         printf("rel %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);
         
         rel_accessors[rel_seg_idx]->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, index, reloc->type, reloc->addend);
         
         if (reloc->last_entry) break;
         reloc++;
      }
   }

   for (int i = 0; i < cro_header->num_static_relocations; i++)
   {
      CRO_Relocation* reloc = cro_header->get_static_reloc(cro_data, i);
      int rel_seg_idx = reloc->seg_offset & 0xf;
      int rel_seg_offs = reloc->seg_offset >> 4;
      int ref_seg_idx = reloc->last_entry;
         
      printf("rel static %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);
         
      rel_accessors[rel_seg_idx]->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, ref_seg_idx, reloc->type, reloc->addend);
   }
	
	elf.save(argv[2]);
}
