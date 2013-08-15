#include <stdlib.h>
#include <assert.h>
#include "hash.h"
static const size_t HASH_TABLE_SIZE = 73;

struct hash_entry {
	unsigned h;
	void *data;
	struct hash_entry *next;
};
struct hash {
	size_t table_size;
	struct hash_entry **table;
};

struct hash *hash_init()
{
	struct hash *h = malloc(sizeof(struct hash));
	assert(h != NULL);
	h->table_size = HASH_TABLE_SIZE;
	h->table = calloc(h->table_size, sizeof(struct hash_entry *));
	assert(h->table != NULL);
	return h;
}

void hash_free(struct hash *h)
{
	for (unsigned i = 0; i < h->table_size; i++)
		while (h->table[i] != NULL) {
			struct hash_entry *nxt = h->table[i]->next;
			free(h->table[i]->data);
			free(h->table[i]);
			h->table[i] = nxt;
		}
	free(h->table);
	free(h);
}

void hash_insert(struct hash *h, unsigned hash, void *data)
{
	int slot = hash % h->table_size;
	struct hash_entry *new = malloc(sizeof(struct hash_entry));
	assert(new != NULL);
	new->h = hash;
	new->data = data;
	new->next = h->table[slot];
	h->table[slot] = new;
}

void *hash_find(struct hash *h, unsigned hash)
{
	int slot = hash % h->table_size;
	for (struct hash_entry * p = h->table[slot]; p; p = p->next) {
		if (p->h == hash)
			return p->data;
	}
	return NULL;
}
