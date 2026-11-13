// SPDX-License-Identifier: MIT
#include <cstdio>
#include "src/zone/pbvh_adapter.h"

int main(int argc, char **argv) {
  if (argc != 2) { printf("RESULT: ERROR give the golden file\n"); return 2; }
  FILE *f = fopen(argv[1], "r");
  if (!f) { printf("RESULT: ERROR cannot read %s\n", argv[1]); return 2; }
  const Aabb scene = {0, 1024000, 0, 1024000, 0, 1024000};
  unsigned x, y, z, want;
  long rows = 0;
  while (fscanf(f, "%u\t%u\t%u\t%u", &x, &y, &z, &want) == 4) {
    Aabb box = {x * 1000LL, x * 1000LL + 1000, y * 1000LL, y * 1000LL + 1000, z * 1000LL, z * 1000LL + 1000};
    uint32_t code = morton_of_aabb(&box, &scene);
    Aabb cell = morton_cell_of(code, 10, &scene);
    if (code != want || cell.min_x != box.min_x || cell.min_y != box.min_y || cell.min_z != box.min_z) {
      printf("MORTON row %ld: cell %u %u %u has code %u and Lean says %u\nRESULT: FAIL\n", rows, x, y, z, code, want);
      return 1;
    }
    rows++;
  }
  fclose(f);
  if (rows < 500) { printf("MORTON only %ld rows\nRESULT: FAIL\n", rows); return 1; }
  printf("MORTON rows=%ld\nRESULT: PASS\n", rows);
  return 0;
}
