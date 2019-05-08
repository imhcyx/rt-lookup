#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#ifdef TRIEBITS
#define RT_TRIE_BITS_PER_NODE   (TRIEBITS)
#else
#define RT_TRIE_BITS_PER_NODE   (1)
#endif

#define RT_TRIE_BITS_MASK       (~((uint32_t)-1 << RT_TRIE_BITS_PER_NODE))
#define RT_TRIE_BRANCHES        (1 << RT_TRIE_BITS_PER_NODE)

struct rt_trie_node {
  struct rt_trie_node *next[RT_TRIE_BRANCHES];
  int port; // -1 for internal nodes
};

struct rt_trie_node *rt_trie_root;
unsigned int rt_trie_nodes;

#define trie_alloc() (rt_trie_nodes++, (struct rt_trie_node *)malloc(sizeof(struct rt_trie_node)))
#define trie_free(x) (free(x), --rt_trie_nodes)

struct rt_entry {
  uint32_t ip;
  int mask;
  int port;
};

struct rt_entry *rt_list;
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

void trie_init() {
  rt_trie_root = trie_alloc();
  memset(rt_trie_root, 0, sizeof(struct rt_trie_node));
  rt_trie_root->port = -1;
}

void trie_add_entry(uint32_t ip, int mask, int port) {
  struct rt_trie_node *node, *p;
  int bits, key;
  int unmasked_bits, i;
  // extend ip to 64 bits in case of RT_TRIE_BITS_PER_NODE being non-factor of 32 (such as 3, 5)
  uint64_t _ip = (uint64_t)ip << 32;

  node = rt_trie_root;

  for (bits = 0; bits < mask - RT_TRIE_BITS_PER_NODE; bits += RT_TRIE_BITS_PER_NODE) {
    key = (_ip >> (64 - RT_TRIE_BITS_PER_NODE - bits)) & RT_TRIE_BITS_MASK;
    p = node->next[key];
    if (!p) {
      p = trie_alloc();
      memset(p, 0, sizeof(struct rt_trie_node));
      p->port = -1;
      node->next[key] = p;
    }
    node = p;
  }

  unmasked_bits = bits + RT_TRIE_BITS_PER_NODE - mask;
  key = (_ip >> (64 - RT_TRIE_BITS_PER_NODE - bits)) & RT_TRIE_BITS_MASK;
  for (i = key; i < key + (1 << unmasked_bits); i++) {
    p = node->next[i];
    if (!p) {
      p = trie_alloc();
      memset(p, 0, sizeof(struct rt_trie_node));
      node->next[i] = p;
    }
    p->port = port;
  }
}

int trie_lookup(uint32_t ip) {
  struct rt_trie_node *node, *p;
  int bits, key;
  int port = -1;
  // extend ip to 64 bits in case of RT_TRIE_BITS_PER_NODE being non-factor of 32 (such as 3, 5)
  uint64_t _ip = (uint64_t)ip << 32;

  node = rt_trie_root;

  for (bits = 0; bits < 32; bits += RT_TRIE_BITS_PER_NODE) {
    key = (_ip >> (64 - RT_TRIE_BITS_PER_NODE - bits)) & RT_TRIE_BITS_MASK;
    node = node->next[key];
    if (!node) break;
    if (node->port >= 0) port = node->port;
  }

  return port;
}

void trie_free_node(struct rt_trie_node *node) {
  int i;
  struct rt_trie_node *p;
  for (i = 0; i < RT_TRIE_BRANCHES; i++) {
    p = node->next[i];
    if (p) trie_free_node(p);
  }
  trie_free(node);
}

void trie_destroy() {
  trie_free_node(rt_trie_root);
}

#ifdef REFGEN
void ref_gen() {
  int i;
  FILE *f = fopen("ref.txt", "w");
  for (i = 0; i < rt_entry_count; i++) {
    fprintf(f, "%d\n", trie_lookup(rt_list[i].ip));
  }
  fclose(f);
}
#endif

int lookup_all() {
  int i;
  int dummy = 0; // in case of the removal of this function in high optimization level
  for (i = 0; i < rt_entry_count; i++) {
    dummy ^= trie_lookup(rt_list[i].ip);
    dummy ^= dummy >> 16;
    dummy <<= 1;
  }
  return dummy;
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

  trie_init();

  while (fscanf(f, "%s %d %d", ipstr, &mask, &port) == 3) {
    ip = ip_from_str(ipstr);
    trie_add_entry(ip, mask, port);
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

exit:
  if (f) fclose(f);
  return ret;
}

void dump_tree(struct rt_trie_node *node, int value, int indent) {
  int i;

  if (!node) return;

  for (i = 0; i < indent; i++)
    printf(" ");
  printf("%d(%d): %d\n", value, indent, node->port);
  for (i = 0; i < RT_TRIE_BRANCHES; i++)
    dump_tree(node->next[i], i, indent + 1);
}

long long micro_time_diff(struct timeval *tv1, struct timeval *tv2) {
  return (tv2->tv_sec - tv1->tv_sec) * 1000000 + (tv2->tv_usec - tv1->tv_usec);
}

int main() {
  struct timeval tv1, tv2;
  int dummy;

  printf("loading data...\n");
  load_data("forwarding-table.txt");
  printf("trie node count: %u total size: %u\n", rt_trie_nodes, rt_trie_nodes * sizeof(struct rt_trie_node));
  //dump_tree(rt_trie_root, 0, 0);

#ifdef REFGEN
  printf("generating reference...\n");
  ref_gen();
#endif

  printf("timing...\n");
  gettimeofday(&tv1, NULL);
  dummy = lookup_all();
  gettimeofday(&tv2, NULL);
  printf("avg. time: %.2lf ns\n", (double)micro_time_diff(&tv1, &tv2) * 1000 / rt_entry_count);
  printf("dummy: %08x\n", dummy); // dummy also acts as the checksum of the results

  trie_destroy();
  free(rt_list);
  return 0;
}