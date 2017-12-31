#include <cstdlib>
#include <string>

#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"

#include <map>

using namespace ELFIO;

typedef struct
{
   std::string name;
   Elf64_Addr addr;
   Elf_Xword size;
   uint8_t bind, type, other;
   Elf_Half section_index;
} ELF_Symbol;

bool ELF_get_symbol(symbol_section_accessor& syma, int index, ELF_Symbol& symbol_out)
{
   return syma.get_symbol(index, symbol_out.name, symbol_out.addr, symbol_out.size, symbol_out.bind, symbol_out.type, symbol_out.section_index, symbol_out.other);
}

bool ELF_get_symbol_by_name(symbol_section_accessor& syma, std::string name, ELF_Symbol& symbol_out)
{
   symbol_out.name = name;
   return syma.get_symbol(name, symbol_out.addr, symbol_out.size, symbol_out.bind, symbol_out.type, symbol_out.section_index, symbol_out.other);
}

int ELF_get_symbol_index_by_name(symbol_section_accessor& syma, std::string name)
{
   for (int i = 0; i < syma.get_symbols_num(); i++)
   {
      ELF_Symbol symbol;
      ELF_get_symbol(syma, i, symbol);
      
      if (symbol.name == name)
         return i;
   }
   
   return -1;
}

size_t align_up(size_t val, size_t align)
{
   return (val + (align - val % align) % align);
}

uint32_t addr_to_segment(elfio& elf, Elf64_Addr addr)
{
   int seg_idx = -1;
   for (int i = 0; i < elf.segments.size(); i++)
   {
      if (addr >= elf.segments[i]->get_virtual_address() && addr < (elf.segments[i]->get_virtual_address() + elf.segments[i]->get_memory_size()))
      {
         seg_idx = i;
         break;
      }
   }
   
   return seg_idx;
}

int counts[3] = {0};
section* add_relocation_section(elfio& elf, int segment_index)
{
   char* secs[3] = {".text", ".rodata", ".data"};
   char rela_name[32];
   snprintf(rela_name, 32, ".rela%s.%u", secs[segment_index], counts[segment_index]++);
   
   printf("Added %s\n", rela_name);
   
   section* rel_sec = elf.sections.add(rela_name);
   rel_sec->set_type(SHT_RELA);
   rel_sec->set_entry_size(elf.get_default_entry_size(SHT_RELA));
   rel_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
   rel_sec->set_info(elf.sections[segment_index+2]->get_index());
   rel_sec->set_overlay(elf.sections[segment_index+2]->get_index());
   rel_sec->set_link(elf.sections[".dynsym"]->get_index());
   rel_sec->set_addr_align(4);
   return rel_sec;
}

int main(int argc, char **argv)
{
   if (argc < 3)
   {
      printf("Usage: %s <input.elf> <inject.elf> <out.elf>\n", argv[0]);
      return -1;
   }

   elfio elf_input;
   elfio elf_inject;
   elfio elf_out;
   
   if (!elf_input.load(argv[1]) | !elf_out.load(argv[1]))
   {
      printf("Failed to load file %s! Exiting...\n", argv[1]);
      return -1;
   }
   
   if (!elf_inject.load(argv[2]))
   {
      printf("Failed to load file %s! Exiting...\n", argv[1]);
      return -1;
   }

   uint32_t next_addr = 0x180;
   uint32_t inject_offsets[5];
   uint32_t new_offsets[5];
   size_t added_size = 0;
   for (int i = 0; i < elf_inject.segments.size(); i++)
   {
      if (i >= elf_out.segments.size()) break;

      inject_offsets[i] = align_up(elf_out.segments[i]->get_memory_size(), 0x4);
      
      if (i == 3)
         inject_offsets[i] = align_up(elf_out.sections[i+2]->get_size(), 0x4);
      
      char *new_data = (char*)calloc(inject_offsets[i] + elf_inject.segments[i]->get_memory_size(), 1);

      // Copy existing data
      if (elf_input.segments[i]->get_file_size())
         memcpy(new_data, elf_input.segments[i]->get_data(), elf_input.segments[i]->get_file_size());
      
      // Concatenate new data
      if (elf_inject.segments[i]->get_file_size())
         memcpy(new_data + inject_offsets[i], elf_inject.segments[i]->get_data(), elf_inject.segments[i]->get_file_size());
      
      // Sections should be in order with .text at 2, then .rodata, .data, .bss, .cro_info
      elf_out.sections[i+2]->set_data(new_data, inject_offsets[i] + elf_inject.segments[i]->get_memory_size());
      elf_out.segments[i]->add_section_index(elf_out.sections[i+2]->get_index(), elf_out.sections[i+2]->get_addr_align());
      
      // Adjust addresses, .data will not be accurate but it doesn't matter really since that will correct with
      // elf2cro anyhow.
      added_size += (inject_offsets[i] + elf_inject.segments[i]->get_memory_size() - elf_input.segments[i]->get_memory_size());
      new_offsets[i] = next_addr;
      elf_out.sections[i+2]->set_address(next_addr);
      elf_out.segments[i]->set_physical_address(next_addr);
      elf_out.segments[i]->set_virtual_address(next_addr);
      elf_out.segments[i]->set_file_size(elf_out.segments[i]->get_file_size() + elf_inject.segments[i]->get_memory_size());
      elf_out.segments[i]->set_memory_size(elf_out.segments[i]->get_memory_size() + elf_inject.segments[i]->get_memory_size());
      
      next_addr = align_up(next_addr + inject_offsets[i] + elf_inject.segments[i]->get_file_size(), 0x4);
   }
   
   symbol_section_accessor syma(elf_out, elf_out.sections[".dynsym"]);
   string_section_accessor stra(elf_out.sections[".dynstr"]);
   symbol_section_accessor syma_in(elf_inject, elf_inject.sections[".dynsym"]);
   
   // Adjust original symbols
   for (int i = 1; i < syma.get_symbols_num(); i++)
   {
      ELF_Symbol symbol;
      ELF_get_symbol(syma, i, symbol);
      
      // Skip imports
      if (!symbol.addr) continue;
      
      
      uint32_t new_addr = symbol.addr - elf_input.segments[addr_to_segment(elf_input, symbol.addr)]->get_physical_address() + new_offsets[addr_to_segment(elf_input, symbol.addr)];
      
      //printf("%s old %x new %x\n", symbol.name.c_str(), symbol.addr, new_addr);
      ((Elf32_Sym*)elf_out.sections[".dynsym"]->get_data())[i].st_value = new_addr;
   }
   
   // Adjust original relocations
   for (int k = 0; k < elf_out.sections.size(); k++)
   {
      section* sec = elf_out.sections[k];
      if (sec->get_type() != SHT_RELA) continue;

      relocation_section_accessor rela_orig(elf_out, sec);
      for (int i = 0; i < rela_orig.get_entries_num(); i++)
      {
         Elf64_Addr offset;
         Elf_Word symbol_idx;
         Elf_Word type;
         Elf_Sxword addend;

         rela_orig.get_entry(i, offset, symbol_idx, type, addend);
    
         ELF_Symbol symbol;
         ELF_get_symbol(syma, symbol_idx, symbol);
         
         uint32_t new_offset = offset - elf_input.segments[addr_to_segment(elf_input, offset)]->get_physical_address() + new_offsets[addr_to_segment(elf_input, offset)];
         uint32_t new_addend = addend;
         if (type == 0x2 || type == 0x16)
         {
            if (addr_to_segment(elf_input, addend) != -1)
            {
               new_addend = addend - elf_input.segments[addr_to_segment(elf_input, addend)]->get_physical_address() + new_offsets[addr_to_segment(elf_input, addend)];
               //printf("Addend %x to %x\n", addend, new_addend);
            }
         }
         else if (type == 0x17) // Relative -> absolute
         {
            int rel_seg_idx = addr_to_segment(elf_input, offset);
            uint32_t seg_offs = new_offset - new_offsets[rel_seg_idx];
            uint32_t orig_value = *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs);
            *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs) = 0;
            
            int32_t relative_target_seg = addr_to_segment(elf_input, orig_value);
            
            if (relative_target_seg == -1 && orig_value == elf_input.segments[0]->get_virtual_address() + elf_input.segments[0]->get_file_size())
            {
               relative_target_seg = 0;
            }
            
            //printf("%x %x %x\n", new_offset, relative_target_seg, orig_value);
            uint32_t relative_target = orig_value - elf_input.segments[relative_target_seg]->get_virtual_address() + new_offsets[relative_target_seg];
            //printf("relative %x %x %x\n", relative_target, seg_offs, relative_target_seg);
            
            ((Elf32_Rela*)sec->get_data())[i].r_info = ELF32_R_INFO(relative_target_seg+1, 2);
            new_addend = relative_target;
         }
         ((Elf32_Rela*)sec->get_data())[i].r_offset = new_offset;
         ((Elf32_Rela*)sec->get_data())[i].r_addend = new_addend;
         
         /*if (offset != new_offset)
            printf("old %x new %x\n", offset, new_offset);*/
      }
   }
   
   // Add in new symbols, and adjust for new offsets
   for (int i = 0; i < syma_in.get_symbols_num(); i++)
   {
      ELF_Symbol symbol;
      ELF_get_symbol(syma_in, i, symbol);

      if (symbol.name == "") continue;
      
      if (!strcmp(symbol.name.c_str() + strlen(symbol.name.c_str()) - strlen("_orig"), "_orig"))
      {
         char *not_orig = (char*)calloc(strlen(symbol.name.c_str()) - strlen("_orig") + 1, 1);
         memcpy(not_orig, symbol.name.c_str(), strlen(symbol.name.c_str()) - strlen("_orig"));
         if (ELF_get_symbol_index_by_name(syma, std::string(not_orig)) != -1)
         {
            //printf("Ignore\n");
            continue;
         }
         
      }
      

      if (ELF_get_symbol_index_by_name(syma, symbol.name) != -1)
      {
         int orig_idx = ELF_get_symbol_index_by_name(syma, symbol.name);
         ELF_Symbol symbol_orig;
         ELF_Symbol symbol_new;
         ELF_get_symbol(syma, orig_idx, symbol_orig);
         
         printf("identical name %s\n", symbol.name.c_str());
         if (symbol.addr)
         {
            // Rename things
            printf("readjusting symbol names\n");
            
            // We have two symbols of the same name defined. The injected name takes precedence,
            // and the original will be renamed to <name>_orig.
            std::string renamed = symbol.name + "_orig";
            uint32_t new_addr = symbol.addr + (symbol.addr ? inject_offsets[addr_to_segment(elf_inject, symbol.addr)] : 0);
            int index = syma.add_symbol(stra, renamed.c_str(), new_addr, symbol.size, symbol.bind, symbol.type, symbol.other, symbol.section_index);
            ELF_get_symbol(syma, index, symbol_new);

            section *sec = elf_out.sections[".dynsym"];
            
            Elf32_Addr temp_value = ((Elf32_Sym*)sec->get_data())[index].st_value;
            Elf_Word temp_size = ((Elf32_Sym*)sec->get_data())[index].st_size;
            unsigned char temp_info = ((Elf32_Sym*)sec->get_data())[index].st_info;
            unsigned char temp_other = ((Elf32_Sym*)sec->get_data())[index].st_other;
            Elf_Half temp_shndx = ((Elf32_Sym*)sec->get_data())[index].st_shndx;
            
            ((Elf32_Sym*)sec->get_data())[index].st_value = ((Elf32_Sym*)sec->get_data())[orig_idx].st_value;
            ((Elf32_Sym*)sec->get_data())[index].st_size = ((Elf32_Sym*)sec->get_data())[orig_idx].st_size;
            ((Elf32_Sym*)sec->get_data())[index].st_info = ((Elf32_Sym*)sec->get_data())[orig_idx].st_info;
            ((Elf32_Sym*)sec->get_data())[index].st_other = ((Elf32_Sym*)sec->get_data())[orig_idx].st_other;
            ((Elf32_Sym*)sec->get_data())[index].st_shndx = ((Elf32_Sym*)sec->get_data())[orig_idx].st_shndx;
            
            ((Elf32_Sym*)sec->get_data())[orig_idx].st_value = temp_value;
            ((Elf32_Sym*)sec->get_data())[orig_idx].st_size = temp_size;
            ((Elf32_Sym*)sec->get_data())[orig_idx].st_info = temp_info;
            ((Elf32_Sym*)sec->get_data())[orig_idx].st_other = temp_other;
            ((Elf32_Sym*)sec->get_data())[orig_idx].st_shndx = temp_shndx;
         }
      }
      else
      {
         printf("Adding %s %i\n", symbol.name.c_str(), addr_to_segment(elf_inject, symbol.addr));
         
         uint32_t new_addr = 0;
         if (symbol.addr)
            new_addr = symbol.addr + inject_offsets[addr_to_segment(elf_inject, symbol.addr)] - elf_inject.segments[addr_to_segment(elf_inject, symbol.addr)]->get_virtual_address() + new_offsets[addr_to_segment(elf_inject, symbol.addr)];

         int index = syma.add_symbol(stra, symbol.name.c_str(), new_addr, symbol.size, symbol.bind, symbol.type, symbol.other, symbol.section_index);
      }
   }
   
   // Add new relocations and adjust
   int last_rela = -1;
   relocation_section_accessor* rel_accessor = nullptr;
   for (int k = 0; k < elf_inject.sections.size(); k++)
   {
      section* sec = elf_inject.sections[k];
      if (sec->get_type() != SHT_RELA && sec->get_type() != SHT_REL) continue;
      
      //printf("%s %x\n", sec->get_name().c_str(), sec->get_info());
      
      int rel_seg_idx = -1;
      int last_rela = -1;
      
      relocation_section_accessor rela(elf_inject, sec);
      for (int i = 0; i < rela.get_entries_num(); i++)
      {
         Elf64_Addr offset;
         Elf_Word symbol_idx;
         Elf_Word type;
         Elf_Sxword addend;

         rela.get_entry(i, offset, symbol_idx, type, addend);
            
         ELF_Symbol symbol;
         ELF_Symbol symbol_real;
         ELF_get_symbol(syma_in, symbol_idx, symbol);
         ELF_get_symbol(syma, ELF_get_symbol_index_by_name(syma, symbol.name), symbol_real);
         
         rel_seg_idx = addr_to_segment(elf_inject, offset);
         uint32_t new_addr = offset + (offset ? inject_offsets[rel_seg_idx] : 0);
         uint32_t new_sym_addr = symbol.addr + (symbol.addr ? inject_offsets[rel_seg_idx] : 0);
         uint32_t new_offset = new_sym_addr - new_offsets[rel_seg_idx];
         //printf("%s %x %x->%x %i %x\n", symbol.name.c_str(), offset, offset, new_addr, rel_seg_idx, symbol_real.addr);
         
         if (last_rela != rel_seg_idx)
         {
            if (rel_accessor != nullptr)
               delete rel_accessor;
            rel_accessor = new relocation_section_accessor(elf_out, add_relocation_section(elf_out, rel_seg_idx));
         }
         
         if ((symbol_real.addr == 0) && (type == 0x2 || type == 0x16)) // Imports
         {
            offset = new_addr;
            symbol_idx = ELF_get_symbol_index_by_name(syma, symbol.name);
            
            uint32_t seg_offs = new_addr - new_offsets[rel_seg_idx];
            uint32_t orig_value = *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs);
            *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs) = 0;

            type = 0x2;
         }
         else if (type == 0x2 || type == 0x16) // ABS32
         {
            offset = new_addr;
            if (symbol.name == "") // Just some generic relocation
            {
               symbol_idx = rel_seg_idx+1;
               addend += new_offset;
            }
            else // We're importing functions from the ELF being injected into, adjust
            {
               symbol_idx = addr_to_segment(elf_out, symbol_real.addr)+1;
               addend += symbol_real.addr;
               type = 0x2;
               
               uint32_t seg_offs = new_addr - new_offsets[rel_seg_idx];
               *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs) = 0;
            }
         }
         else if (type == 0x17) // Relative -> absolute
         {
            uint32_t seg_offs = new_addr - new_offsets[rel_seg_idx];
            uint32_t orig_value = *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs);
            *(uint32_t*)(elf_out.sections[rel_seg_idx+2]->get_data() + seg_offs) = 0;
            
            //new_offsets[addr_to_segment(elf_inject, orig_value)] + inject_offsets[addr_to_segment(elf_inject, orig_value)]
            uint32_t relative_target_seg = addr_to_segment(elf_inject, orig_value);
            uint32_t relative_target = orig_value - elf_inject.segments[relative_target_seg]->get_virtual_address() + new_offsets[addr_to_segment(elf_inject, orig_value)] + inject_offsets[relative_target_seg];
            //printf("relative %x %x %x\n", relative_target, seg_offs, addr_to_segment(elf_inject, orig_value));
            
            symbol_idx = relative_target_seg+1;
            offset = new_addr;
            addend = relative_target;
            type = 0x2;
         }

         rel_accessor->add_entry(offset, symbol_idx, type, addend);
         last_rela = rel_seg_idx;
      }
   }

   elf_out.save(argv[3]);
}
