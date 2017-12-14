#include <cstdlib>
#include <string>

#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"
#include "cro.h"

using namespace ELFIO;

void push_data(void*& cro_data, size_t& cro_size, const void* data, size_t size)
{
   cro_data = realloc(cro_data, cro_size + size);
   if (data != NULL)
      memcpy((char*)cro_data + cro_size, data, size);
   else
      memset((char*)cro_data + cro_size, 0, size);
   cro_size += size;
}

void push_segment(void* cro_data, size_t& cro_size, segment* seg)
{
   push_data(cro_data, cro_size, seg->get_data(), seg->get_file_size());
}

void alloc_align_up(void*& alloc, size_t& size, size_t align, uint8_t fill = 0)
{
   size_t old_size = size;
   size = (size + (align - size % align) % align);
   alloc = realloc(alloc, size);
   memset((char*)alloc + old_size, fill, size - old_size);
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
   
   CRO_Header *cro_header;
   void* cro_data = calloc(1, sizeof(CRO_Header));
   size_t cro_size = sizeof(CRO_Header);
   size_t segment_start[5];
   size_t segment_size[5];
   
   alloc_align_up(cro_data, cro_size, 0x80);
   size_t cro_header_size = cro_size;

   cro_header = (CRO_Header*)cro_data;
   cro_header->magic = MAGIC_CRO0;
   
   // Push .text segment
   segment_start[SEG_TEXT] = cro_size;
   push_segment(cro_data, cro_size, elf.segments[SEG_TEXT]);
   
   // Push .rodata segment
   segment_start[SEG_RODATA] = cro_size;
   segment_size[SEG_TEXT] = cro_size - segment_start[SEG_TEXT];
   push_segment(cro_data, cro_size, elf.segments[SEG_RODATA]);
   alloc_align_up(cro_data, cro_size, 0x1000);
   segment_size[SEG_RODATA] = cro_size - segment_start[SEG_RODATA];
   
   // Set .bss size
   cro_header->size_bss = elf.segments[SEG_BSS]->get_memory_size();
   
   //
   // Begin linking info
   //
   
   // Push CRO module name
   std::string cro_filename = std::string(argv[2]);
   std::string cro_name = cro_filename.substr(0, cro_filename.find_last_of("."));
   
   cro_header->offs_mod_name = cro_size;
   cro_header->offs_name = cro_size;
   cro_header->size_name = cro_name.size() + 1;
   
   push_data(cro_data, cro_size, cro_name.c_str(), cro_name.size() + 1);

   
   // Push segments
   alloc_align_up(cro_data, cro_size, 0x4);
   size_t cro_segment_start = cro_size;
   for (int i = 0; i < 5; i++)
   {
      CRO_Segment segment;
      segment.offset = segment_start[i];
      segment.size = segment_size[i];
      segment.type = i;
      
      // CRO header segment(?)
      if (i == 4)
      {
         segment.offset = 0;
         segment.size = 0/*cro_header_size*/;
         segment.type = SEG_TEXT;
      }
      
      push_data(cro_data, cro_size, &segment, sizeof(CRO_Segment));
   }
   cro_header->offs_segments = cro_segment_start;
   cro_header->num_segments = 5;
   
   // Push exported symbols
   symbol_section_accessor syma(elf, elf.sections[".dynsym"]);
   CRO_Symbol* exports = (CRO_Symbol*)((char*)cro_data + cro_size);
   cro_header->offs_symbol_exports = cro_size;
   cro_header->offs_index_exports = syma.get_symbols_num();
   push_data(cro_data, cro_size, NULL, sizeof(CRO_Symbol) * syma.get_symbols_num());
   
   // Push index exports (TODO)
   cro_header->offs_index_exports = cro_size;
   cro_header->num_index_exports = syma.get_symbols_num();
   
   // Push export tree
   CRO_ExportTreeEntry* exportTree = (CRO_ExportTreeEntry*)((char*)cro_data + cro_size);
   push_data(cro_data, cro_size, NULL, sizeof(CRO_ExportTreeEntry) * syma.get_symbols_num());
   
   size_t export_strtab_offset = cro_size;
   size_t export_strtab_size;
   for (int i = 0; i < syma.get_symbols_num(); i++)
   {
      std::string name;
      Elf64_Addr addr;
      Elf_Xword size;
      uint8_t bind, type, other;
      Elf_Half section_index;
      syma.get_symbol(i, name ,addr, size, bind, type, section_index, other);
      
      if (section_index != 0 && name != "")
      {
         size_t name_offset = cro_size;
         exports[i].offs_name = name_offset;
         exports[i].seg_offset = addr;
         
         //TODO: export tree
         //TODO: control offset
         //TODO: OnLoad
         //TODO: OnExit
         //TODO: OnUnresolved
         
         push_data(cro_data, cro_size, name.c_str(), name.length()+1);
      }
   }
   export_strtab_size = cro_size - export_strtab_offset;
   
   cro_header->offs_export_strtab = export_strtab_offset;
   cro_header->size_export_strtab = export_strtab_size;
   alloc_align_up(cro_data, cro_size, 0x4);
   
   // Push imports
   
   // Push data
   segment_start[SEG_DATA] = cro_size;
   /*push_segment(cro_data, cro_size, elf.segments[SEG_DATA]);
   alloc_align_up(cro_data, cro_size, 0x1000, 0xCC);*/
   segment_size[SEG_DATA] = cro_size - segment_start[SEG_DATA];
   
   // Finalize
   cro_header->offs_text = segment_start[SEG_TEXT];
   cro_header->size_text = segment_size[SEG_TEXT] + segment_size[SEG_RODATA];
   cro_header->offs_data = segment_start[SEG_DATA];
   cro_header->size_data = segment_size[SEG_DATA];
   cro_header->size_file = cro_size;
   
   FILE* cro_file = fopen(argv[2], "wb");
   if (!cro_file)
   {
      printf("Failed to open file %s for writing! Exiting...\n", argv[2]);
      return -1;
   }

   fwrite(cro_header, sizeof(uint8_t), cro_size, cro_file);
   fclose(cro_file);
}
