# 深入理解Ptmalloc2

由于已经不是4月份一无所知的状态了，就不再全部copy wiki的，只记录些关键点和自己的体会。



## 申请内存块



### __libc_malloc

源码：

```c
void *__libc_malloc(size_t bytes){ // 无符号整型！
    mstate ar_ptr;
    void *victim;
    void *(*hook)(size_t,const void *) = atomic_forced_read(__malloc_hook); 
    if(__builtin_expect(hook != NULL,0)) // 检查是否有__malloc_hook
        return (*hook)(bytes,RETURN_ADDRESS(0));
    ...
}
```

(C的函数指针**太优雅**了！)

几个点：

1.  申请的size在malloc时会自动转换为**无符号整型**
2. **__malloc_hook**



### _int_malloc

实际上__libc_malloc也就是对 `_int_malloc`的简单封装。

`_int_malloc`是内存分配的核心函数。刚好学了OS的内存管理，这里copy下wiki上介绍的核心思想。

1. 根据用户申请的内存块大小和响应大小chunk通常使用的频度，依次实现不同的分配方法。
2. 由小到大依次检查不同的bin中是否有响应的空闲块可以满足请求的内存。
3. 当所有的空闲chunk都无法满足时，会考虑top chunk。
4. 当top chunk也无法满足，堆分配器才会进行内存块申请。



一些结构体啥的就略过了。



#### fast bin

源码：

```c
if(){
    do{
        
    }while();
    if(victim!=0){
        /*
        检查大小和索引是否一致。
        chunksize: 获得当前victim大小。
        fastbin_index: 计算对应fastbin的索引 (eg. 0x7f -> 0x70)
        */
     	if(__builtin_expect(fastbin_index(chunksize(vitim)) != idx),0){
            errstr = "";
        errout:
            ;
        }
        
    }
}
```

几个点：

1. 还是一样，size都是无符号整型。

2. fast bin 是**LIFO**，所以分配的时候从fastbin的**头**结点开始取chunk。

3. fastbin分配的时候有个小检查，**检查取到的chunk大小与对应的fastbin的索引是否一致。**

   这里索引就是0x20,0x30,...0x70。这也就是为什么打fastbin attck需要伪造size的原因。

   经典 `__malloc_hook-0x23`的fake chunk，0x7f -> 索引为 0x70，所以add(0x60)。



#### small bin

源码：

```c
```

几个点：

1. 获取small bin **最后一个chunk**。也就是链表尾部的chunk，也是最先进来的chunk。

2. 分的情况要复杂点。（bin是否为空？若非空，是否初始化？（这里涉及到fastbin的合并））

3. 同样的有一些小检查。

   在small bin中有空闲堆块的情况下，检查：

   ```c
   bck = victim->bk;
   if(__glibc_unlikely(bck->fd != victim)){
       errstr = "";
       goto errout;
   }
   ```

   （虽说感觉并没有起到什么安全的防范作用。。。）



#### large bin

emmm，还没学到large bin 的利用。。。但是large bin的一些特性还是值得先记录下。

large bin中并没有直接去扫描对应bin中的chunk，而是先利用`malloc_consolidate`函数处理**fast bin**中的chunk，将有可能能够合并的chunk先合并后放入**unsorted bin**中，不能够合并的就直接放到**unsorted bin**中。然后再在下面的大循环中进行相应的处理。

（核心思想就是减少内存碎片，更充分的利用已有空间。）



也提到了这是一个“大循环”，源码也比较繁杂，各种细节操作也很多。更多的点留到以后再来补。

核心思想就是先放进unsorted bin后再进行处理，分到其他的bin中供使用。

感觉重点就是会先放入unsorted bin，然后切割。也就是unsorted bin和堆块切分是利用点罢。