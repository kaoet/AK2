#pragma once
struct hash;
struct hash * hash_init();
void hash_insert(struct hash *h,unsigned hash,void *data);
void *hash_find(struct hash *h,unsigned hash);
void hash_free(struct hash *h);
