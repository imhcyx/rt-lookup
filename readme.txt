build lookup for reference generation:
gcc lookup.c -DREFGEN -o lookup

build lookup:
gcc lookup.c -DTRIEBITS=x -O3 -o lookup
where x indicates the number of ways for the multi-way trie (default is 1)

build poptrie:
gcc poptrie.c -O3 -msse4
