#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#define setbit(x, i)    (x |= (uint64_t)1 << i)
#define clearbit(x, i)  (x &= ~((uint64_t)1 << i))
#define getbit(x, i)    (((x) >> i) & 1)

struct poptrie_node {
  uint64_t vector;
  uint64_t leafvec;
  struct poptrie_node *base1;
  int *base0;
} *poptrie;

struct rt_entry {
  uint32_t ip;
  int mask;
  int port;
  int ref;
} *rt_list;
unsigned int rt_entry_count;

uint32_t ip_from_str(char* str) {
  uint32_t ip = 0;

  while (1) {
    ip <<= 8;
    ip |= atoi(str) & 0xff;
    str = strchr(str, '.');
    if (!str) break;
    str++;
  }

  return ip;
}

struct poptrie_node *poptrie_alloc_node(unsigned int n) {
  struct poptrie_node *p = malloc(n * sizeof(struct poptrie_node));
  memset(p, 0, n * sizeof(struct poptrie_node));
  return p;
}

int *poptrie_alloc_leaf(unsigned int n) {
  int *p = malloc(n * sizeof(int));
  return p;
}

void poptrie_free_subnode(struct poptrie_node *p) {
  int i, count;

  free(p->base0);

  count = __builtin_popcountll(p->vector);
  for (i = 0; i < count; i++)
    poptrie_free_subnode(&p->base1[i]);

  free(p->base1);
}

void poptrie_init() {
  poptrie = poptrie_alloc_node(1);
}

void poptrie_destroy() {
  poptrie_free_subnode(poptrie);
  free(poptrie);
}

void poptrie_fill_unset_leaves(struct poptrie_node *p, int port) {
  int i;

  if (!p->base0) p->base0 = poptrie_alloc_leaf(64);
  for (i = 0; i < 64; i++) {
    if (getbit(p->vector, i)) {
      poptrie_fill_unset_leaves(&p->base1[i], port);
    }
    else if (!getbit(p->leafvec, i)) {
      setbit(p->leafvec, i);
      p->base0[i] = port;
    }
  }
}

void poptrie_add_entry(uint32_t ip, int len, int port) {
  struct poptrie_node *p = poptrie;
  int offset;
  int key, max, i;
  // extend ip to 64 bits for 0 padding in the last chunk
  uint64_t _ip = (uint64_t)ip << 32;

  // fill all internal nodes in the mask
  for (offset = 0; offset < len - 6; offset += 6) {
    key = _ip >> (64 - 6 - offset) & 0x3f;
    setbit(p->vector, key);
    if (!p->base1) p->base1 = poptrie_alloc_node(64);

    // if child is a leaf node, convert it to an internal node
    if (getbit(p->leafvec, key)) {
      int old = p->base0[key];
      clearbit(p->leafvec, key);
      p->base1[key].leafvec = (uint64_t)-1;
      p->base1[key].base0 = poptrie_alloc_leaf(64);
      for (i = 0; i < 64; i++)
        p->base1[key].base0[i] = old;
    }

    p = &p->base1[key];
  }

  // fill all leaf nodes for unmasked bits in this chunk
  if (!p->base0) p->base0 = poptrie_alloc_leaf(64);
  key = _ip >> (64 - 6 - offset) & 0x3f;
  max = key + (1 << (offset + 6 - len));
  for (i = key; i < max; i++) {
    setbit(p->leafvec, i);
    p->base0[i] = port;

    // if child is an internal node, fill all unset children of its
    if (getbit(p->vector, i))
      poptrie_fill_unset_leaves(&p->base1[i], port);
  }
}

void poptrie_compress(struct poptrie_node *p) {
  int i, count;
  int prevport;
  struct poptrie_node *base1;
  int *base0;

  // fill nonexistent leaf nodes
  if (p->base0) {
    for (i = 0; i < 64; i++) {
      if (!getbit(p->vector, i) && !getbit(p->leafvec, i)) {
        p->base0[i] = -1;
      }
    }
  }

  // compress base0
  if (p->base0) {
    count = 0;
    prevport = -2; // should be an unused value
    for (i = 0; i < 64; i++) {
      if (p->base0[i] != prevport) {
        prevport = p->base0[i];
        p->base0[count++] = prevport;
        setbit(p->leafvec, i);
      }
      else {
        clearbit(p->leafvec, i);
      }
    }

    base0 = poptrie_alloc_leaf(count);
    memcpy(base0, p->base0, count * sizeof(int));
    free(p->base0);
    p->base0 = base0;
  }

  // compress base1
  if (p->base1) {
    count = 0;
    for (i = 0; i < 64; i++) {
      if (getbit(p->vector, i)) {
        p->base1[count++] = p->base1[i];
      }
    }

    base1 = poptrie_alloc_node(count);
    memcpy(base1, p->base1, count * sizeof(struct poptrie_node));
    free(p->base1);
    p->base1 = base1;
  }

  // compress child nodes
  if (p->base1)
    for (i = 0; i < count; i++)
      poptrie_compress(&p->base1[i]);
}

int poptrie_lookup(uint32_t ip) {
  struct poptrie_node *p;
  int offset;
  int key;
  int bc;
  // extend ip to 64 bits for 0 padding in the last chunk
  uint64_t _ip = (uint64_t)ip << 32;

  p = poptrie;

  for (offset = 0; offset < 32; offset += 6) {
    key = _ip >> (64 - 6 - offset) & 0x3f;
    if (getbit(p->vector, key)) {
      bc = __builtin_popcountll(p->vector & ((uint64_t)2 << key) - 1);
      p = &p->base1[bc - 1];
    }
    else if (p->base0) {
      bc = __builtin_popcountll(p->leafvec & ((uint64_t)2 << key) - 1);
      return p->base0[bc - 1];
    }
    else {
      return -1;
    }
  }

  return -1;
}

int load_data(char *filename) {
  int ret = 1, i;
  char ipstr[20];
  uint32_t ip;
  int mask, port;
  FILE *f = fopen(filename, "r");

  if (!f) {
    fprintf(stderr, "failed to load file %s\n", filename);
    ret = 0;
    goto exit;
  }

  while (fscanf(f, "%s %d %d", ipstr, &mask, &port) == 3) {
    ip = ip_from_str(ipstr);
    poptrie_add_entry(ip, mask, port);
    rt_entry_count++;
  }

  fseek(f, 0, SEEK_SET);
  rt_list = malloc(rt_entry_count * sizeof(struct rt_entry));

  for (i = 0; i < rt_entry_count; i++) {
    fscanf(f, "%s %d %d", ipstr, &mask, &port);
    rt_list[i].ip = ip_from_str(ipstr);;
    rt_list[i].mask = mask;
    rt_list[i].port = port;
  }

  fclose(f);

exit:
  if (f) fclose(f);
  return ret;
}

int load_ref(char *filename) {
  int ret = 1, i;
  int ref;
  FILE *f = fopen(filename, "r");

  if (!f) {
    fprintf(stderr, "failed to load file %s\n", filename);
    ret = 0;
    goto exit;
  }

  for (i = 0; i < rt_entry_count; i++) {
    fscanf(f, "%d", &ref);
    rt_list[i].ref = ref;
  }

  fclose(f);

exit:
  if (f) fclose(f);
  return ret;
}

void lookup_all_verify() {
  int i;
  int result;
  for (i = 0; i < rt_entry_count; i++) {
    result = poptrie_lookup(rt_list[i].ip);
    if (result != rt_list[i].ref) {
      printf("%d: ip=%08x expected %d returned %d\n", i, rt_list[i].ip, rt_list[i].ref, result);
      return;
    }
  }
}

int lookup_all() {
  int i;
  int dummy = 0; // in case of the removal of this function in high optimization level
  for (i = 0; i < rt_entry_count; i++) {
    dummy ^= poptrie_lookup(rt_list[i].ip);
    dummy ^= dummy >> 16;
    dummy <<= 1;
  }
  return dummy;
}

void dump_tree_uncompressed(struct poptrie_node *node, int indent) {
  int i, j;

  if (!node) return;

  for (i = 0; i < 64; i++) {
    if (getbit(node->vector, i)) {
      for (j = 0; j < indent; j++)
        printf(" ");
      printf("%02x (%d):\n", i, indent);
      dump_tree_uncompressed(&node->base1[i], indent + 1);
    }
    else if (getbit(node->leafvec, i)) {
      for (j = 0; j < indent; j++)
        printf(" ");
      printf("%02x (%d): %d\n", i, indent, node->base0[i]);
    }
  }
}

void dump_tree(struct poptrie_node *node, int indent) {
  int i, j;
  int bc;

  if (!node) return;

  for (i = 0; i < 64; i++) {
    if (getbit(node->vector, i)) {
      bc = __builtin_popcountll(node->vector & ((uint64_t)2 << i) - 1);
      for (j = 0; j < indent; j++)
        printf(" ");
      printf("%02x (%d):\n", i, indent);
      dump_tree(&node->base1[bc - 1], indent + 1);
    }
    else if (node->base0) {
      bc = __builtin_popcountll(node->leafvec & ((uint64_t)2 << i) - 1);
      for (j = 0; j < indent; j++)
        printf(" ");
      printf("%02x (%d): %d\n", i, indent, node->base0[bc - 1]);
    }
  }
}

long long micro_time_diff(struct timeval *tv1, struct timeval *tv2) {
  return (tv2->tv_sec - tv1->tv_sec) * 1000000 + (tv2->tv_usec - tv1->tv_usec);
}

int main() {
  struct timeval tv1, tv2;
  int dummy;

  poptrie_init();

  printf("loading data...\n");
  load_data("forwarding-table.txt");
  load_ref("ref.txt");

  printf("compressing poptrie...\n");
  poptrie_compress(poptrie);

  //dump_tree(poptrie, 0);

  lookup_all_verify();

  printf("timing...\n");
  gettimeofday(&tv1, NULL);
  dummy = lookup_all();
  gettimeofday(&tv2, NULL);
  printf("avg. time: %.2lf ns\n", (double)micro_time_diff(&tv1, &tv2) * 1000 / rt_entry_count);
  printf("dummy: %08x\n", dummy); // dummy also acts as the checksum of the results

  poptrie_destroy();
  free(rt_list);
  return 0;
}