[一道题目学习glibc 2.32_tcachebin 2.32 key-CSDN博客](https://blog.csdn.net/qq_40712959/article/details/115696356)

[高版本glibc的tcache和fastbin指针加密机制_malloc(): unaligned tcache chunk detected-CSDN博客](https://blog.csdn.net/qq_51474381/article/details/115829513)



所以2.29以后要泄露的不只是libc了，还要泄露key（![img](https://img-blog.csdnimg.cn/20210418160114480.png)就是这个东西，第一个chunk的fd<<12，去掉第三位的heap基地址，因为第一个被free的chunk其实是移位后xor了个0所以会这样。)



## glibc-2.31 没有PROTECT_PTR

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```



## glibc-2.32 safe-linking

核心思想：将**指针的地址**右移12位后再和**指针本身**xor

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```



对应的，tcache相关操作，tcache_put和tcache_get也进行了更改

`tcache_put`

```c
static __always_inline void *
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;
//2.31引入的新机制
  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

```

在向tcache的bin放入chunk时，会将其bk指针(`tcache_entry->key`)改写为所放入的tcache，防止double free

除此之外，还会将其**fd指针地址**与`tcache->entry[tc_idx]`异或存储。



`tcache_get`

```c
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}

```

从tcache bin中取chunk时,会对取出的chunk进行反异或操作,同时将其bk指针(tcache_entry->key)置零



## bypass safe-linking

bypass safe-linking机制需要用到uaf或者double free之类的漏洞,同时释放tcache到一个空闲tacahe bin中,

此时由于tcache bin中没有空闲chunk,tcache->entry[tc_idx]=0,故

> PROTECT_PTR (&e->next, tcache->entries[tc_idx])== PROTECT_PTR (分配到的chunk地址->fd,0)==((分配到的chunk地址->fd)>>12)^0 ==(分配到的chunk地址->fd)>>12

此时若存在uaf 或者double free,

可以泄露出leak_addr= (&malloced_chunk->fd)>>12位置,

则**heap_base=leak_addr<<12**

同样的,若存在堆溢出、double free等漏洞,可以改写chunk的bk指针,

即tcache_entry->key为0,以绕过tcache的double free检查