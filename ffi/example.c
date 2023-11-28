#include "ptrsx.h"
#include <stdio.h>

int main() {
  // int pid = 26149;

  // init
  PointerSearcherX *ptr = ptrsx_init();
  int ret = 0;

  // // create a pointer map in file
  // ret = create_pointer_map_file(ptr, pid, true, "26149.info.txt", "26149.bin");
  // if (ret != 0) {
  //   const char *error = get_last_error(ptr);
  //   printf("%s\n", error);
  //   return 0;
  // }

  load_modules_info_file(ptr, "26149.info.txt");
  load_pointer_map_file(ptr, "26149.bin");

  // // create a pointer map in memory
  // ret = create_pointer_map(ptr, pid, true);
  // if (ret != 0) {
  //   const char *error = get_last_error(ptr);
  //   printf("%s\n", error);
  //   return 0;
  // }

  // get available base address modules
  ModuleList modules = get_modules_info(ptr);
  for (int i = 0; i < modules.len; i++) {
    printf("[%zx %zx %s]\n", modules.data[i].start, modules.data[i].end,
           modules.data[i].name);
  }

  // select some base address modules of interest
  struct Module module[] = {
      {modules.data[0].start, modules.data[0].end, modules.data[0].name},
      {modules.data[1].start, modules.data[1].end, modules.data[1].name},
  };
  ModuleList select_modules = {2, module};

  struct Params params = {0x600002990020, 4, 3, 200, 200};

  scanner_pointer_chain(ptr, select_modules, params, "26149.scandata");

  ptrsx_free(ptr);
  return 0;
}
