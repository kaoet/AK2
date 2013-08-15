#pragma once
struct vector;
struct vector *vector_init();
void vector_push(struct vector *v, const void *data);
const void **vector_getdata(struct vector *v);
