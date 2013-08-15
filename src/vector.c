#include "vector.h"
#include <assert.h>
#include <stdlib.h>

struct vector {
	const void **arr;
	size_t alloc;
	size_t size;
};

struct vector *vector_init()
{
	struct vector *new = malloc(sizeof(struct vector));
	assert(new != NULL);
	new->arr = malloc(0);
	new->size = 0;
	new->alloc = 0;
	return new;
}

void vector_push(struct vector *v, const void *data)
{
	if (v->size + 1 > v->alloc) {
		assert(realloc(v->arr, sizeof(void *) * (v->size + 1)) != NULL);
		v->alloc = v->size + 1;
	}
	v->arr[v->size++] = data;
}

const void **vector_getdata(struct vector *v)
{
	return v->arr;
}
