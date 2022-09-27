#include <cstdlib>
#include <fstream>
#include <unordered_map>

#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"
#include "cro.h"

using namespace ELFIO;

int counts[3] = {0};
section* add_relocation_section(elfio& elf, section** sections, section* dynsym_sec, int segment_index)
{
   char* secs[3] = {".text", ".rodata", ".data"};
   char rela_name[32];
   snprintf(rela_name, 32, ".rela%s.%u", secs[segment_index], counts[segment_index]++);
   
   section* rel_sec = elf.sections.add(rela_name);
   rel_sec->set_type(SHT_RELA);
   rel_sec->set_entry_size(elf.get_default_entry_size(SHT_RELA));
   rel_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
   rel_sec->set_info(sections[segment_index]->get_index());
   rel_sec->set_overlay(sections[segment_index]->get_index());
   rel_sec->set_link(dynsym_sec->get_index());
   rel_sec->set_addr_align(4);
   return rel_sec;
}

int main(int argc, char **argv)
{
   if (argc < 3)
   {
      printf("Usage: %s <input.cro> <output.elf> [cro_list.txt] [code.bin]\n", argv[0]);
      return -1;
   }
   
   FILE* cro_file = fopen(argv[1], "rb");
   if (!cro_file)
   {
      printf("Failed to open file %s! Exiting...\n", argv[1]);
      return -1;
   }
   
   bool is_static = false;
   FILE* static_file;
   void* static_data = nullptr;
   uint32_t static_size = 0;
   if (argc > 4)
   {
      static_file = fopen(argv[4], "rb");
      if (!static_file)
      {
         printf("Failed to open file %s! Exiting...\n", argv[4]);
         return -1;
      }
      
      is_static = true;
      fseek(static_file, 0, SEEK_END);
      static_size = ftell(static_file);
      static_data = malloc(static_size);
      
      fseek(static_file, 0, SEEK_SET);
      fread(static_data, sizeof(uint8_t), static_size, static_file);
      fclose(static_file);
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
   elf.set_type(ET_REL);
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
      
      sec->set_addr_align(4);
      if (cro_segments[i].type != SEG_BSS)
      {
         sec->set_address(cro_segments[i].offset);
         if (is_static)
         {
            if (i < 4)
               sec->set_data((char*)static_data + cro_segments[i].offset - 0x100000, cro_segments[i].size);
         }
         else
            sec->set_data((char*)cro_data + cro_segments[i].offset, cro_segments[i].size);
      }
      else
      {
         sec->set_size(cro_header->size_bss);
         seg->set_memory_size(cro_segments[i].size);
         seg->set_file_size(cro_segments[i].size);
      }
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
      dynsym_sec->set_info(5+1);
      dynsym_sec->set_overlay(sections[SEG_TEXT]->get_index());
      dynsym_sec->set_addr_align(4);
   }
   symbol_section_accessor symd(elf, dynsym_sec);
   
   for (int i = 0; i < 5; i++)
   {
      symd.add_symbol(0, segments[i]->get_virtual_address(), 0, STB_LOCAL, STT_SECTION, 0, sections[i]->get_index());
   }
   
   int last_rela = -1;
   relocation_section_accessor* rel_accessor = nullptr;
   
   for (int i = 0; i < cro_header->num_symbol_exports; i++)
   {
      CRO_Symbol* symbol = cro_header->get_export(cro_data, i);
      int seg_idx = symbol->seg_offset & 0xf;
      int seg_offs = symbol->seg_offset >> 4;
      //printf("%x - %x %x\n", symbol->seg_offset, seg_idx, seg_offs);
      //printf("%s\n", (char*)cro_data + symbol->offs_name);
      
      symd.add_symbol(stra, (char*)cro_data + symbol->offs_name, segments[seg_idx]->get_virtual_address() + seg_offs, 0, STB_GLOBAL, STT_NOTYPE, 0, sections[seg_idx]->get_index());
   }
   
   for (int i = 0; i < cro_header->num_index_exports; i++)
   {
      CRO_Symbol* symbol = cro_header->get_index_export(cro_data, i);
      int seg_idx = symbol->seg_offset & 0xf;
      int seg_offs = symbol->seg_offset >> 4;
      //printf("index %x - %x %x\n", symbol->seg_offset, seg_idx, seg_offs);
      
      char name[256];
      snprintf(name, 256, "export_index_%u", symbol->offs_name);
      symd.add_symbol(stra, name, segments[seg_idx]->get_virtual_address() + seg_offs, 0, STB_GLOBAL, STT_NOTYPE, 0, sections[seg_idx]->get_index());
   }
   
   for (int i = 0; i < cro_header->num_index_exports; i++)
   {
      CRO_Symbol* symbol = cro_header->get_index_export(cro_data, i);
      int seg_idx = symbol->seg_offset & 0xf;
      int seg_offs = symbol->seg_offset >> 4;
      //printf("index %x - %x %x\n", symbol->seg_offset, seg_idx, seg_offs);
      
      char name[256];
      snprintf(name, 256, "import_index_%u", symbol->offs_name);
      symd.add_symbol(stra, name, segments[seg_idx]->get_virtual_address() + seg_offs, 0, STB_GLOBAL, STT_NOTYPE, 0, sections[seg_idx]->get_index());
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
         
         //printf("rel %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);
         
         if (last_rela != rel_seg_idx)
         {
            if (rel_accessor != nullptr)
               delete rel_accessor;
            rel_accessor = new relocation_section_accessor(elf, add_relocation_section(elf, sections, dynsym_sec, rel_seg_idx));
         }
         rel_accessor->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, index, reloc->type, reloc->addend);
         last_rela = rel_seg_idx;
         
         if (reloc->last_entry) break;
         reloc++;
      }
   }
   
   int module_count = 0;
   int remaining_in_module = cro_header->get_module_entry(cro_data, module_count)->import_indexed_symbol_num;
   for (int i = 0; i < cro_header->num_index_imports; i++)
   {
      CRO_ModuleEntry* module = cro_header->get_module_entry(cro_data, module_count);

      CRO_Symbol* symbol = cro_header->get_index_import(cro_data, i);
      uint32_t patch_offs = symbol->seg_offset;
      
      char name[256];
      snprintf(name, 256, "import_index_%s_%u", module->get_name(cro_data), symbol->offs_name);
      int index = symd.add_symbol(stra, name, 0x0, 0, STB_GLOBAL, STT_NOTYPE, 0, 0);
      
      if (patch_offs) {
         CRO_Relocation* reloc = (CRO_Relocation*)((char*)cro_data + patch_offs);
         while(1)
         {
            int rel_seg_idx = reloc->seg_offset & 0xf;
            int rel_seg_offs = reloc->seg_offset >> 4;
            
            //printf("rel index %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);
            
            if (last_rela != rel_seg_idx)
            {
               if (rel_accessor != nullptr)
                  delete rel_accessor;
               rel_accessor = new relocation_section_accessor(elf, add_relocation_section(elf, sections, dynsym_sec, rel_seg_idx));
            }
            rel_accessor->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, index, reloc->type, reloc->addend);
            last_rela = rel_seg_idx;
            
            if (reloc->last_entry) break;
            reloc++;
         }
      }

      remaining_in_module -= 1;
      if (remaining_in_module <= 0) {
         module_count++;
         remaining_in_module = cro_header->get_module_entry(cro_data, module_count)->import_indexed_symbol_num;
      }
   }
   
   module_count = 0;
   remaining_in_module = cro_header->get_module_entry(cro_data, module_count)->import_anonymous_symbol_num;
   for (int i = 0; i < cro_header->num_offset_imports; i++)
   {
      CRO_ModuleEntry* module = cro_header->get_module_entry(cro_data, module_count);

      CRO_Symbol* symbol = cro_header->get_offset_import(cro_data, i);
      uint32_t patch_offs = symbol->seg_offset;
      int seg_idx = symbol->offs_name & 0xf;
      int seg_offs = symbol->offs_name >> 4;
      
      char name[256];
      snprintf(name, 256, "offset_import_%s_%x_%x", module->get_name(cro_data), seg_idx, seg_offs);
      int index = symd.add_symbol(stra, name, 0x0, 0, STB_GLOBAL, STT_NOTYPE, 0, 0);
      
      if (patch_offs) {
         CRO_Relocation* reloc = (CRO_Relocation*)((char*)cro_data + patch_offs);
         while(1)
         {
            int rel_seg_idx = reloc->seg_offset & 0xf;
            int rel_seg_offs = reloc->seg_offset >> 4;
            
            //printf("rel offset %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);
            
            if (last_rela != rel_seg_idx)
            {
               if (rel_accessor != nullptr)
                  delete rel_accessor;
               rel_accessor = new relocation_section_accessor(elf, add_relocation_section(elf, sections, dynsym_sec, rel_seg_idx));
            }
            rel_accessor->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, index, reloc->type, reloc->addend);
            last_rela = rel_seg_idx;
            
            if (reloc->last_entry) break;
            reloc++;
         }
      }

      remaining_in_module -= 1;
      if (remaining_in_module <= 0) {
         module_count++;
         remaining_in_module = cro_header->get_module_entry(cro_data, module_count)->import_anonymous_symbol_num;
      }
   }

   for (int i = 0; i < cro_header->num_static_relocations; i++)
   {
      CRO_Relocation* reloc = cro_header->get_static_reloc(cro_data, i);
      int rel_seg_idx = reloc->seg_offset & 0xf;
      int rel_seg_offs = reloc->seg_offset >> 4;
      int ref_seg_idx = reloc->last_entry;
         
      //printf("rel static %x %x %x %x\n", reloc->seg_offset, reloc->type, reloc->addend, reloc->last_entry);

      if (last_rela != rel_seg_idx)
      {
         if (rel_accessor != nullptr)
            delete rel_accessor;
         rel_accessor = new relocation_section_accessor(elf, add_relocation_section(elf, sections, dynsym_sec, rel_seg_idx));
      }
      rel_accessor->add_entry(segments[rel_seg_idx]->get_virtual_address() + rel_seg_offs, ref_seg_idx+1, reloc->type, segments[ref_seg_idx]->get_virtual_address() + reloc->addend);
      last_rela = rel_seg_idx;
   }

   // Gather offsets that CROs are interested in
   std::unordered_map<uint32_t, int> already_added_map;
   if (argc > 3)
   {
      std::ifstream file(argv[3]);
      if (file.is_open()) {
         std::string line;
         while (std::getline(file, line)) {
            FILE* cro_file_2 = fopen(line.c_str(), "rb");
            if (!cro_file_2)
            {
               printf("Failed to open file %s! Exiting...\n", line.c_str());
               return -1;
            }

            fseek(cro_file_2, 0, SEEK_END);
            uint32_t cro_size_2 = ftell(cro_file_2);
            void* cro_data_2 = malloc(cro_size_2);
            
            fseek(cro_file_2, 0, SEEK_SET);
            fread(cro_data_2, sizeof(uint8_t), cro_size_2, cro_file_2);
            fclose(cro_file_2);
            
            CRO_Header* cro_header_2 = (CRO_Header*)cro_data_2;
            printf("Loading info from CRO %s\n", cro_header_2->get_name(cro_data_2));

            if (!strcmp(cro_header->get_name(cro_data), cro_header_2->get_name(cro_data))) {
               free(cro_data_2);
               continue;
            }

            module_count = 0;
            remaining_in_module = cro_header_2->get_module_entry(cro_data_2, module_count)->import_anonymous_symbol_num;
            for (int i = 0; i < cro_header_2->num_offset_imports; i++)
            {
               CRO_ModuleEntry* module = cro_header_2->get_module_entry(cro_data_2, module_count);

               CRO_Symbol* symbol = cro_header_2->get_offset_import(cro_data_2, i);
               uint32_t patch_offs = symbol->seg_offset;
               int seg_idx = symbol->offs_name & 0xf;
               int seg_offs = symbol->offs_name >> 4;

               uint32_t static_addr = segments[seg_idx]->get_virtual_address() + seg_offs;
               if (!strcmp(module->get_name(cro_data_2), cro_header->get_name(cro_data)) && already_added_map.find(static_addr) == already_added_map.end()) {
                  char name[256];
                  snprintf(name, 256, "offset_import_%s_%x_%x", module->get_name(cro_data_2), seg_idx, seg_offs);
                  int index = symd.add_symbol(stra, name, static_addr, 0, STB_GLOBAL, STT_NOTYPE, 0, sections[seg_idx]->get_index());

                  already_added_map[static_addr] = 1;
                  printf("%s\n", name);
               }

               remaining_in_module -= 1;
               if (remaining_in_module <= 0) {
                  module_count++;
                  remaining_in_module = cro_header_2->get_module_entry(cro_data_2, module_count)->import_anonymous_symbol_num;
               }
            }

            free(cro_data_2);
         }
         file.close();
      }
   }
   
   elf.save(argv[2]);

   return 0;
}
