#include <stddef.h>
#include <stdint.h>

typedef struct PointerScan PointerScan;

typedef struct PointerVerify PointerVerify;

typedef struct Param {
  size_t addr;
  size_t depth;
  size_t node;
  size_t left;
  size_t right;
} Param;

struct PointerScan *ptrs_init(void);

void ptrs_free(struct PointerScan *ptr);

const char *get_last_error(void);

int ptrs_create_pointer_map(struct PointerScan *ptr, int pid, bool align,
                            const char *info_path, const char *bin_path);

int ptrs_load_pointer_map(struct PointerScan *ptr, const char *info_path,
                          const char *bin_path);

int ptrs_scan_pointer_chain(struct PointerScan *ptr, struct Param params,
                            const char *file_path);

int compare_two_file(const char *file1, const char *file2, const char *outfile);

struct PointerVerify *ptrv_init(void);

void ptrv_free(struct PointerVerify *ptr);

int ptrv_set_proc(struct PointerVerify *ptr, int pid);

int ptrv_invalid_filter(struct PointerVerify *ptr, const char *_file);

int ptrv_value_filter(struct PointerVerify *ptr, const char *_file,
                      const uint8_t *_data, size_t _size);
