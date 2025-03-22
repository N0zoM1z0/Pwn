确实看winmt师傅的就很容易明白利用的原理和技巧。



# tcache_stashing_unlink_attack

写的很好，直接搬过来了。

---

先来看`house of lore`，

如果能够修改`small bin`的某个`free chunk`的`bk`为`fake chunk`，并且通过修改`fake chunk`的`fd`为该`free chunk`，绕过`__glibc_unlikely( bck->fd != victim )`检查，就可以通过申请堆块得到这个`fake chunk`，进而进行任意地址的读写操作。

当在高版本`libc`下有`tcache`后，将会更加容易达成上述目的，因为当从`small bin`返回了一个所需大小的`chunk`后，在将剩余堆块放入`tcache bin`的过程中（**stash机制**），**除了检测了第一个堆块的`fd`指针**外，都缺失了`__glibc_unlikely (bck->fd != victim)`的双向链表完整性检测。

又`calloc()`会越过`tcache`取堆块，因此有了如下`tcache_stashing_unlink_attack`的攻击手段，并同时实现了`libc`的泄露或将任意地址中的值改为很大的数（与`unsorted bin attack`很类似）。

1. 假设目前`tcache bin`中已经有五个堆块，并且相应大小的`small bin`中已经有两个堆块，由`bk`指针连接为：`chunk_A<-chunk_B`。

2. 利用漏洞修改`chunk_A`的`bk`为`fake chunk`，并且修改`fake chunk`的`bk`为`target_addr - 0x10`。

3. 通过`calloc()`越过`tcache bin`，直接从`small bin`中取出`chunk_B`返回给用户，并且会将`chunk_A`以及其所指向的`fake chunk`放入`tcache bin`（这里只会检测`chunk_A`的`fd`指针是否指向了`chunk_B`）。

   ```c
   while ( tcache->counts[tc_idx] < mp_.tcache_count
       && (tc_victim = last (bin) ) != bin) //验证取出的Chunk是否为Bin本身（Smallbin是否已空）
   {
    if (tc_victim != 0) //成功获取了chunk
    {
        bck = tc_victim->bk; //在这里bck是fake chunk的bk
        //设置标志位
        set_inuse_bit_at_offset (tc_victim, nb);
        if (av != &main_arena)
            set_non_main_arena (tc_victim);
    
        bin->bk = bck;
        bck->fd = bin; //关键处
    
        tcache_put (tc_victim, tc_idx); //将其放入到tcache中
    }
   }
   ```

4. 在`fake chunk`放入`tcache bin`之前，执行了`bck->fd = bin;`的操作（这里的`bck`就是`fake chunk`的`bk`，也就是`target_addr - 0x10`），故`target_addr - 0x10`的`fd`，也就`target_addr`地址会被写入一个与`libc`相关大数值（可利用）。

5. 再申请一次，就可以从`tcache`中获得`fake chunk`的控制权。



综上，此利用可以完成**获得任意地址的控制权**和**在任意地址写入大数值**两个任务，这两个任务当然也可以拆解分别完成。

1. 获得任意地址`target_addr`的控制权：在上述流程中，直接将`chunk_A`的`bk`改为`target_addr - 0x10`，并且保证`target_addr - 0x10`的`bk`的`fd`为一个可写地址（一般情况下，使`target_addr - 0x10`的`bk`，即`target_addr + 8`处的值为一个可写地址即可）。
2. 在任意地址`target_addr`写入大数值：在`unsorted bin attack`后，有时候要修复链表，在链表不好修复时，可以采用此利用达到同样的效果，在高版本`glibc`下，`unsorted bin attack`失效后，此利用应用更为广泛。在上述流程中，需要使`tcache bin`中原先有六个堆块，然后将`chunk_A`的`bk`改为`target_addr - 0x10`即可。

此外，让`tcache bin`中不满七个，就又在`smallbin`中有同样大小的堆块，并且只有`calloc`，可以利用堆块分割后，残余部分进入`unsorted bin`实现。