#include <cstdlib>
#include <string>

#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"
#include "cro.h"
#include "bit_trie.h"

#include <map>

using namespace ELFIO;

typedef struct
{
   void* cro_data;
   size_t cro_size;
   CRO_Header* cro_header;
} CRO_Context;

typedef struct
{
   std::string name;
   Elf64_Addr addr;
   Elf_Xword size;
   uint8_t bind, type, other;
   Elf_Half section_index;
} ELF_Symbol;

void push_data(CRO_Context& context, const void* data, size_t size)
{
   context.cro_data = realloc(context.cro_data, context.cro_size + size);
   if (data != NULL)
      memcpy((char*)context.cro_data + context.cro_size, data, size);
   else
      memset((char*)context.cro_data + context.cro_size, 0, size);
   context.cro_size += size;
   context.cro_header = (CRO_Header*)context.cro_data;
}

void push_segment(CRO_Context& context, segment* seg)
{
   push_data(context, seg->get_data(), seg->get_file_size());
}

void cro_align_up(CRO_Context& context, size_t align, uint8_t fill = 0)
{
   size_t old_size = context.cro_size;
   context.cro_size = (context.cro_size + (align - context.cro_size % align) % align);
   context.cro_data = realloc(context.cro_data, context.cro_size);
   context.cro_header = (CRO_Header*)context.cro_data;
   memset((char*)context.cro_data + old_size, fill, context.cro_size - old_size);
}

uint32_t cro_addr_to_segment(elfio& elf, Elf64_Addr addr)
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

uint32_t cro_addr_to_segment_addr(elfio& elf, Elf64_Addr addr)
{
   int seg_idx = cro_addr_to_segment(elf, addr);
   
   if (seg_idx == -1) return -1;
   
   return ((addr - elf.segments[seg_idx]->get_virtual_address()) << 4) | (seg_idx & 7);
}

void ELF_get_symbol(symbol_section_accessor& syma, int index, ELF_Symbol& symbol_out)
{
   syma.get_symbol(index, symbol_out.name, symbol_out.addr, symbol_out.size, symbol_out.bind, symbol_out.type, symbol_out.section_index, symbol_out.other);
}

int main(int argc, char **argv)
{
   if (argc < 3)
   {
      printf("Usage: %s <input.elf> <output.cro>\n", argv[0]);
      return -1;
   }

   elfio elf;
   
   if (!elf.load(argv[1]))
   {
      printf("Failed to load file %s! Exiting...\n", argv[1]);
      return -1;
   }
   
   CRO_Context cro_ctx;
   cro_ctx.cro_data = calloc(1, sizeof(CRO_Header));
   cro_ctx.cro_size = sizeof(CRO_Header);
   cro_ctx.cro_header = (CRO_Header*)cro_ctx.cro_data;
   
   
   size_t segment_start[5];
   size_t segment_size[5];
   
   cro_align_up(cro_ctx, 0x80);
   size_t cro_header_size = cro_ctx.cro_size;

   cro_ctx.cro_header->magic = MAGIC_CRO0;
   
   // Push .text segment
   segment_start[SEG_TEXT] = cro_ctx.cro_size;
   push_segment(cro_ctx, elf.segments[SEG_TEXT]);
   
   // Push .rodata segment
   cro_align_up(cro_ctx, 0x1000);
   segment_start[SEG_RODATA] = cro_ctx.cro_size;
   segment_size[SEG_TEXT] = cro_ctx.cro_size - segment_start[SEG_TEXT];
   push_segment(cro_ctx, elf.segments[SEG_RODATA]);
   segment_size[SEG_RODATA] = cro_ctx.cro_size - segment_start[SEG_RODATA];
   cro_align_up(cro_ctx, 0x1000);
   size_t text_total_size = cro_ctx.cro_size - segment_start[SEG_TEXT];
   
   // Set .bss size
   segment_start[SEG_BSS] = 0;
   segment_size[SEG_BSS] = elf.segments[SEG_BSS]->get_memory_size();

   //
   // Begin linking info
   //
   
   // Push CRO module name
   std::string cro_filename = std::string(argv[2]);
   std::string cro_name = cro_filename.substr(0, cro_filename.find_last_of("."));
   
   cro_ctx.cro_header->offs_mod_name = cro_ctx.cro_size;
   cro_ctx.cro_header->offs_name = cro_ctx.cro_size;
   cro_ctx.cro_header->size_name = cro_name.size() + 1;
   
   push_data(cro_ctx, cro_name.c_str(), cro_name.size() + 1);

   
   // Push segments
   cro_align_up(cro_ctx, 0x4);
   cro_ctx.cro_header->offs_segments = cro_ctx.cro_size;
   cro_ctx.cro_header->num_segments = 5; //TODO?
   push_data(cro_ctx, NULL, sizeof(CRO_Segment) * cro_ctx.cro_header->num_segments);
   
   // Push exported symbols
   symbol_section_accessor syma(elf, elf.sections[".dynsym"]);
   
   size_t count_exports = 0;
   size_t count_imports = 0;
   size_t export_strtab_size = 0;
   size_t import_strtab_size = 0;
   for (int i = 0; i < syma.get_symbols_num(); i++)
   {
      ELF_Symbol symbol;
      ELF_get_symbol(syma, i, symbol);
      
      if (symbol.name == "") continue;
      
      if (symbol.section_index != 0)
      {
         count_exports++;
         export_strtab_size += symbol.name.length() + 1;
      }
      else
      {
         count_imports++;
         import_strtab_size += symbol.name.length() + 1;
      }
   }
   
   // Push symbol exports
   cro_ctx.cro_header->offs_symbol_exports = cro_ctx.cro_size;
   cro_ctx.cro_header->num_symbol_exports = count_exports;
   push_data(cro_ctx, NULL, sizeof(CRO_Symbol) * count_exports);

   // Push export tree
   cro_ctx.cro_header->offs_export_tree = cro_ctx.cro_size;
   cro_ctx.cro_header->num_export_tree = count_exports;
   push_data(cro_ctx, NULL, sizeof(CRO_ExportTreeEntry) * count_exports);

   // Push index exports (TODO)
   cro_ctx.cro_header->offs_index_exports = cro_ctx.cro_size;
   cro_ctx.cro_header->num_index_exports = 0;

   // Push export strtab
   size_t export_strtab_offset = cro_ctx.cro_size;
   push_data(cro_ctx, NULL, export_strtab_size);
   
   // Stub Control, OnLoad, OnUnload, Unresolved funcs
   cro_ctx.cro_header->offs_control = 0xffffffff;
   cro_ctx.cro_header->offs_prologue = 0xffffffff;
   cro_ctx.cro_header->offs_epilogue = 0xffffffff;
   cro_ctx.cro_header->offs_unresolved = 0xffffffff;
   
   cro_ctx.cro_header->offs_export_strtab = export_strtab_offset;
   cro_ctx.cro_header->size_export_strtab = export_strtab_size;
   cro_align_up(cro_ctx, 0x4);
   
   // Push import data
   
   // Count up allocations
   
   size_t import_relocs_count = 0;
   size_t export_relocs_count = 0;
   
   // Count relocs

   for (int k = 0; k < elf.sections.size(); k++)
   {
      section* sec = elf.sections[k];
      if (sec->get_type() != SHT_RELA && sec->get_type() != SHT_REL) continue;
      
      relocation_section_accessor rela(elf, sec);
      for (int i = 0; i < rela.get_entries_num(); i++)
      {
         Elf64_Addr offset;
         Elf_Word symbol_idx;
         Elf_Word relType;
         Elf_Sxword addend;

         rela.get_entry(i, offset, symbol_idx, relType, addend);
            
         ELF_Symbol symbol;
         ELF_get_symbol(syma, symbol_idx, symbol);
         
         if (symbol.section_index == 0 && symbol.name != "")
            import_relocs_count++;
         else
            export_relocs_count++;
      }
   }
   
   // Import modules (TODO)
   cro_ctx.cro_header->offs_import_module = cro_ctx.cro_size;
   
   // Import patches
   cro_ctx.cro_header->offs_import_patches = cro_ctx.cro_size;
   cro_ctx.cro_header->num_import_patches = import_relocs_count;
   push_data(cro_ctx, NULL, sizeof(CRO_Relocation) * import_relocs_count);
   
   // Import symbols
   cro_ctx.cro_header->offs_symbol_imports = cro_ctx.cro_size;
   cro_ctx.cro_header->num_symbol_imports = count_imports;
   push_data(cro_ctx, NULL, sizeof(CRO_Symbol) * count_imports);
   
   // Import indexes (TODO)
   cro_ctx.cro_header->offs_index_imports = cro_ctx.cro_size;
   
   // Import offset imports (TODO)
   cro_ctx.cro_header->offs_offset_imports = cro_ctx.cro_size;
   
   // Import strtab
   cro_ctx.cro_header->offs_import_strtab = cro_ctx.cro_size;
   cro_ctx.cro_header->size_import_strtab = import_strtab_size;
   push_data(cro_ctx, NULL, import_strtab_size);
   cro_align_up(cro_ctx, 0x4);
   
   // Export offsets (TODO)
   cro_ctx.cro_header->offs_offset_exports = cro_ctx.cro_size;
   
   // Export unk (TODO?)
   cro_ctx.cro_header->offs_unk = cro_ctx.cro_size;
   
   // Static relocations
   cro_ctx.cro_header->offs_static_relocations = cro_ctx.cro_size;
   cro_ctx.cro_header->num_static_relocations = export_relocs_count;
   push_data(cro_ctx, NULL, sizeof(CRO_Relocation) * export_relocs_count);

   // Push data
   segment_start[SEG_DATA] = cro_ctx.cro_size;
   push_segment(cro_ctx, elf.segments[SEG_DATA]);
   cro_ctx.cro_header->size_data = cro_ctx.cro_size - segment_start[SEG_DATA];
   cro_align_up(cro_ctx, 0x1000, 0xCC);
   segment_size[SEG_DATA] = cro_ctx.cro_size - segment_start[SEG_DATA];

   // Write import/export patches
   size_t import_reloc_count = 0;
   size_t static_reloc_count = 0;
   CRO_Relocation* import_relocs = (CRO_Relocation*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_import_patches);
   CRO_Relocation* static_relocs = (CRO_Relocation*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_static_relocations);
   std::map<Elf_Word, int> symbol_to_patches;

   Elf_Word last_import_symbol_idx;
   for (int k = 0; k < elf.sections.size(); k++)
   {
      section* sec = elf.sections[k];
      if (sec->get_type() != SHT_RELA && sec->get_type() != SHT_REL) continue;

      relocation_section_accessor rela(elf, sec);
      for (int i = 0; i < rela.get_entries_num(); i++)
      {
         Elf64_Addr offset;
         Elf_Word symbol_idx;
         Elf_Word relType;
         Elf_Sxword addend;

         rela.get_entry(i, offset, symbol_idx, relType, addend);
         
         ELF_Symbol symbol;
         ELF_get_symbol(syma, symbol_idx, symbol);
         
         if (symbol.section_index == 0 && symbol.name != "")
         {
            import_relocs[import_reloc_count].seg_offset = cro_addr_to_segment_addr(elf, offset);
            import_relocs[import_reloc_count].type = relType;
            import_relocs[import_reloc_count].last_entry = 1;

            if (symbol_to_patches[symbol_idx] == 0)
               symbol_to_patches[symbol_idx] = import_reloc_count;

            if (last_import_symbol_idx == symbol_idx)
               import_relocs[import_reloc_count-1].last_entry = 0;

            import_relocs[import_reloc_count++].addend = addend;

            last_import_symbol_idx = symbol_idx;
         }
         else
         {
            int sym_seg = cro_addr_to_segment(elf, symbol.addr);
            int sym_add = 0;
            if (sym_seg == -1)
               sym_seg = 0;
            else
               sym_add = symbol.addr - elf.segments[sym_seg]->get_virtual_address();
            //printf("%x %x %x\n", sym_seg, sym_add, symbol.addr);
            
            if (relType == 0x15)
               relType = 2;
               
            if (relType == 0x17)
            {
               int offs_seg = cro_addr_to_segment(elf, offset);
               int offs_addr = elf.segments[offs_seg]->get_virtual_address();
               int offs_add = offset - offs_addr;
               void* seg_data = cro_ctx.cro_header->get_segment_data(cro_ctx.cro_data, offs_seg);
               
               uint32_t val_to_change = *(uint32_t*)((char*)cro_ctx.cro_data + offs_addr + offs_add);
               *(uint32_t*)((char*)cro_ctx.cro_data + elf.segments[offs_seg]->get_virtual_address() + offs_add) = 0;
               
               // Adjust the existing value and find the segment
               offs_seg = cro_addr_to_segment(elf, val_to_change);
               offs_addr = elf.segments[offs_seg]->get_virtual_address();
               
               val_to_change -= offs_addr;
               addend += val_to_change;
               sym_add = val_to_change;
               sym_seg = offs_seg;
               
               //printf("%x (seg %x) %x+%x %x\n", offset, offs_seg, offs_addr, offs_add, val_to_change);
               
               relType = 2;
            }

            static_relocs[static_reloc_count].seg_offset = cro_addr_to_segment_addr(elf, offset);
            static_relocs[static_reloc_count].type = relType;
            static_relocs[static_reloc_count].last_entry = sym_seg;
            if (sec->get_type() == SHT_RELA)
               static_relocs[static_reloc_count].addend = addend - symbol.addr;
            else
               static_relocs[static_reloc_count].addend = sym_add;
            
            static_reloc_count++;
         }
      }
   }
   
   // Write symbol exports + index exports + tree
   size_t export_name_offset = cro_ctx.cro_header->offs_export_strtab;
   size_t import_name_offset = cro_ctx.cro_header->offs_import_strtab;
   size_t export_name_count = 0;
   size_t import_name_count = 0;
   CRO_Symbol* exportSymbols = (CRO_Symbol*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_symbol_exports);
   CRO_Symbol* importSymbols = (CRO_Symbol*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_symbol_imports);
   CRO_ExportTreeEntry* exportTree = (CRO_ExportTreeEntry*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_export_tree);
   for (int i = 0; i < syma.get_symbols_num(); i++)
   {
      ELF_Symbol symbol;
      ELF_get_symbol(syma, i, symbol);
      
      if (symbol.section_index != 0 && symbol.name != "")
      {
         //printf("%s %x\n", symbol.name.c_str(), symbol.section_index);
         exportSymbols[export_name_count].offs_name = export_name_offset;
         exportSymbols[export_name_count++].seg_offset = cro_addr_to_segment_addr(elf, symbol.addr);
         
         if (symbol.name == "nnroControlObject_")
         {
            cro_ctx.cro_header->offs_control = cro_addr_to_segment_addr(elf, symbol.addr);
         }
         //TODO: export tree
         //TODO: control offset
         //TODO: OnLoad
         //TODO: OnExit
         //TODO: OnUnresolved
         
         memcpy((char*)cro_ctx.cro_data + export_name_offset, symbol.name.c_str(), symbol.name.length()+1);
         export_name_offset += symbol.name.length()+1;
      }
      else if (symbol.section_index == 0 && symbol.name != "")
      {
         //printf("%s %x\n", symbol.name.c_str(), symbol.section_index);
         importSymbols[import_name_count].offs_name = import_name_offset;
         importSymbols[import_name_count++].seg_offset = cro_ctx.cro_header->offs_import_patches + symbol_to_patches[i] * sizeof(CRO_Relocation);
         
         memcpy((char*)cro_ctx.cro_data + import_name_offset, symbol.name.c_str(), symbol.name.length()+1);
         import_name_offset += symbol.name.length()+1;
      }
   }
   
   // Export Tree
   std::vector<std::pair<std::string, int> > exportsAndIndexes;
   for (int i = 0; i < export_name_count; i++)
   {
      char* expName = (char*)cro_ctx.cro_data + cro_ctx.cro_header->get_export(cro_ctx.cro_data, i)->offs_name;
      std::string expNameStr(expName);
      exportsAndIndexes.push_back(std::pair<std::string, int>(expNameStr, i));
   }

   std::size_t max_bit_length = 0;
   for (const auto& pair : exportsAndIndexes)
   {
      if (pair.first.size() > max_bit_length)
         max_bit_length = pair.first.size();
   }
   max_bit_length *= 8;

   bit_trie<std::string, int, decltype(&string_tester)> example(exportsAndIndexes.begin(), exportsAndIndexes.end(), max_bit_length, &string_tester);

   int treeCount = 0;
   for (auto& node : example.nodes)
   {
      CRO_ExportTreeEntry* entry = cro_ctx.cro_header->get_export_tree_entry(cro_ctx.cro_data, treeCount);
      
      entry->test_bit = static_cast<uint16_t>(node.bit_address) % 8;
      entry->test_byte = static_cast<uint16_t>(node.bit_address) / 8;
      entry->left.next_index = node.left.offset + treeCount;
      entry->left.is_end = node.left.end;
      entry->right.next_index = node.right.offset + treeCount++;
      entry->right.is_end = node.right.end;
      entry->export_index = node.value;
      
      if (treeCount == 1)
         entry->right.is_end = false;
      
      //printf("bit %x of byte %04x, %04x %04x \t\t(%s)\n", entry->test_bit, entry->test_byte, entry->left.raw, entry->right.raw, (char*)cro_ctx.cro_data + cro_ctx.cro_header->get_export(cro_ctx.cro_data, entry->export_index)->offs_name);
   }
   
   // Finalize
   cro_ctx.cro_header->offs_text = segment_start[SEG_TEXT];
   cro_ctx.cro_header->size_text = text_total_size;
   cro_ctx.cro_header->offs_data = segment_start[SEG_DATA];
   
   if (elf.sections[".bss"] != nullptr)
      cro_ctx.cro_header->size_bss = elf.sections[".bss"]->get_size();

   CRO_Segment* cro_segments = (CRO_Segment*)((char*)cro_ctx.cro_data + cro_ctx.cro_header->offs_segments);
   for (int i = 0; i < cro_ctx.cro_header->num_segments; i++)
   {
      CRO_Segment* segment = &cro_segments[i];
      segment->offset = segment_start[i];
      segment->size = elf.segments[i]->get_memory_size();
      segment->type = i;
      
      // CRO header segment(?)
      if (i == 4)
      {
         segment->offset = 0;
         segment->size = 0/*cro_header_size*/;
         segment->type = SEG_TEXT;
      }
   }
   
   cro_ctx.cro_header->size_file = cro_ctx.cro_size;
   
   FILE* cro_file = fopen(argv[2], "wb");
   if (!cro_file)
   {
      printf("Failed to open file %s for writing! Exiting...\n", argv[2]);
      return -1;
   }

   printf("Writing 0x%zx bytes\n", cro_ctx.cro_size);
   fwrite(cro_ctx.cro_data, sizeof(uint8_t), cro_ctx.cro_size, cro_file);
   fclose(cro_file);
}
