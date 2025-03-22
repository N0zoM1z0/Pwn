# Glibc高版本堆利用方法总结

> 截止到目前，主要总结在`2.35~2.37`之间仍然残存的堆利用手法。



进入到`glibc-2.31`之后，很多原有的堆利用方法就失效，因此`glibc`给堆分配机制陆陆续续打上了很多`patch`，目前来看，与堆利用有关的`patch`有：

- `tcachebin`堆指针异或加密（`glibc-2.32`引入）
- `tcahebin`链的数量检查（`glibc-2.33`引入）
- `fastbin`堆指针异或加密（`glibc-2.32`引入）
- 堆内存对齐检查（`glibc-2.32`引入）
- 移除`__malloc_hook`和`__free_hook`（`glibc-2.34`引入）
- 引入`tcache_key`作为`tcache`的`key`检查（`glibc-2.34`引入）
- `__malloc_assert`移除掉`IO`处理函数（`glibc-2.36`引入）
- 移除`__malloc_assert`函数（`glibc-2.37`引入）
- 将`global_max_fast`的数据类型修改为`uint8_t`（`glibc-2.37`引入）



# 1-攻击向量

## 1-1 tcachebin

事实上，在泄露地址的基础上劫持`tcachebin`的`next`，依然可以任意地址分配。

### 1-1-1 绕过指针保护

绕过指针异或的保护方法主要有两种：

- 当`tcachebin`链表中只有一个`chunk`的时候，此时`chunk->next << 12`即可得到堆地址。

- 当`tcachebin`链表的前两个`chunk`的地址相差不是很大的时候，可以用下面的公式计算：

  ```python
  def calc_heap(addr):
      s = hex(addr)[2:]
      s = [int(x, base=16) for x in s]
      res = s.copy()
      for i in range(9):
          res[3+i] ^= res[i]
      res = "".join([hex(x)[2:] for x in res])
      return int16_ex(res)
  ```

  这里的`addr`就是头部`chunk`的加密后的`next`，只泄露一次就能还原出来。

### 1-1-2 劫持tcache_ptheread_struct

这个结构体的重要性不言而喻，劫持了这个结构体可以控制`tcachebin`的分配。一般可以用`tcachebin stash unlink`或者`largebin attack`劫持。

### 1-1-3 修改线程tcache变量

在`tls`区域，有一个线程变量`tcache`，如果能用`largebin attack`修改`tcache`变量，也可以控制`tcache`的分配。

### 1-1-4 修改mp_结构体

关注与`tcache`有关的几个变量：

```c
struct malloc_par
{
	//......
#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};
```

修改掉`tcache_bins`可以把很大的`chunk`用`tcachebin`管理；修改掉`tcache_count`可以控制链表的`chunk`的数量。`tcache_max_bytes`目前没啥用，`tcache_unsorted_limit`可以影响`unsortedbin`链表的遍历过程。

## 1-2 fastbin

### 1-2-1 house of corrosion

使用的范围只能在`2.35~2.37`，进入到`2.37`之后，`global_max_fast`的类型被修改为`int8_t`，使用该技巧可以控制的地址范围大大缩小。

有关`house of corrosion`的技巧可以参考[House-of-Corrosion 一种新的堆利用技巧 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/6862#toc-5)。

### 1-2-2 tcache reverse into fastbin

目前检查了对齐，所以要注意控制的地址要是`0x?0`结尾，否则报错。利用效果是任意地址写一个`libc`地址。

虽然`0x?0`写的是加密后的堆地址，但是`0x?8`会写上`tcache_key`，这也是可以利用的点。而且，在写上地址后，还能分配到该处。其利用过程如下：

- 分配`13`个`fastbin`范围内的`chunk`，假设大小为`A`
- 全部释放这`13`个`chunk`
- 分配`7`个，把`tcachebin[A]`耗尽
- 把`fastbin`最后一个`chunk`的`fd`修改为`addr`
- 调用一次`malloc(A)`即可触发`tcache reverse into fastbin`，可以分配到`addr`，也能给`addr/addr+8`处写上地址/数

## 1-3 smallbin

### 1-3-1 house of lore

很显然，`house of lore`依然可以使用，但是`house of lore`使用的时候，一方面是需要满足`victim->fd->bk == victim`；另一方面，需要绕过下面讲的`tcache stash unlink`流程。除此之外，还需要注意内存对齐的问题。

### 1-3-2 tcache stash unlink attack

在我之前的博客中，分析`house of rust`的时候总结过这个利用手法。

第一个技巧叫 `tcachebin stash unlinking`，下面称之为 `TSU` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `8` 个 `smallbin chunk` 的 `bk` 为 `addr`
- 分配 `malloc(A)` 的时候，`addr+0x10` 会被写一个 `libc` 地址

第二个技巧叫 `tcachebin stash unlinking+`，下面称之为 `TSU+` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `7` 个 `smallbin chunk` 的 `bk` 为 `addr`，还要保证 `addr+0x18` 是一个合法可写的地址
- 分配 `malloc(A)` 的时候，`addr` 会被链入到 `tcachebin`，也就是可以分配到 `addr` 处

可以看到，和`fastbin reverse into tcache`的攻击方法很类似，但是得到的效果不一样。`TSU`可以在任意地址写`libc`地址，而`TSU+`除了可以写`libc`地址，还能再任意地址分配。

## 1-4 largebin

目前能用的`largebin attack`只能使用下面这个分支：

```c
/* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      //......
                  }
                  //......
              }
```

效果是可以任意地址写堆地址。

`largebin attack`往往会与其他攻击方法结合起来，因为其写地址的能力，可以修改变量，所以常常用来构造写原语。

### 1-4-1 house of husk

`house of husk`方法仍然可以利用，需要找到一个格式化字符串的场景，且打`house of husk`的时候，至少需要两次格式化字符串。

### 1-4-2 libc/ld上的变量

`libc/ld`的地址空间上关键变量非常多，比如`_IO_list_all`，`pointer_guard`、`tcache`等等。具体的方法会在相关的篇幅里面进行详细说明和补充。

## 1-5 IO_FILE

### 1-5-1 house of kiwi

在这个[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=ac8047cdf326504f652f7db97ec96c0e0cee052f)里面将`__malloc_assert`的实现逻辑修改了。

![image-20230310102503481](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\heap\Glibc高版本堆利用方法总结\images\image-20230310102503481.png)

也就是说，在`glibc-2.36`及其之后，`house of kiwi`的利用链失效了。

而在这个[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=9001cb1102cddba54f0e84e147dfbb0356067356)，直接使用默认的`assert`，`__malloc_assert`被删掉了：

![image-20230310102759826](https://image.roderickchan.cn/img/image-20230310102759826.png)

### 1-5-2 house of emma

只要`_IO_cookie_jumps`还在，这个方法就能继续使用。但是，由于`poniter_guard`处于`ld`的地址空间，所以某些场景是需要爆破的。

### 1-5-3 house of obstack

`glibc-2.36`的时候，`_IO_obstack_jumps`被去掉了，但是还有其他方法可以触发调用链。

`glibc-2.37`开始这个方法的调用链为：`__printf_buffer_as_file_overflow -> __printf_buffer_flush -> __printf_buffer_flush_obstack->__obstack_newchunk`。

### 1-5-4 house of apple1/2/3

- `apple1`需要和其他技巧结合使用，可以任意地址写堆地址
- `apple2`利用的`_wide_vtable`缺乏校验调用函数指针
- `apple3`利用`shlib_handle`去绕过只指针加密调用函数指针

## 1-6 _rtld_global

### 1-6-1 house of banana

整体来看，就是`hosue of banana`的利用

### 1-6-2 利用link_map

围绕`link_map`有很多利用技巧，比如之前有使用格式化字符串修改掉`link_map->l_addr`，可以让函数解析后的地址被写入到其他地址处。而`house of banana`的本质也是围绕`link_map`做利用。

## 1-7 libc.got

### 1-7-1 libc.got in IO

比如高版本`house of pig`没有办法覆写`hook`指针，因为这些指针都被删掉了，那么可以覆写`libc.got`项，在`IO`处理函数中存在着`memcpy/memmove`等函数，当这些函数被调用的时候会`jmp`到对应的`libc.got`存储的地址，因此可以控制`libc.got`的内容来劫持`RIP`。

### 1-7-2 libc.got in malloc_printerr

此外，在`malloc`中的`malloc_printerr`和`assert`，都会调用到`strlen`的`got`，因此，在高版本中可劫持该函数的`got`，来控制`RIP`。

具体来看，就是在`__libc_message`中有调用`strlen`：

```c
/* Abort with an error message.  */
void
__libc_message (enum __libc_message_action action, const char *fmt, ...)
{
 // ......
      if (cp[0] == '%' && cp[1] == 's')
	{
	  str = va_arg (ap, const char *);
	  len = strlen (str); // 这里调用了strlen
	  cp += 2;
	}
      //.....
  }
}
```

## 1-8 heap_info/malloc_state

攻击堆管理中最核心的数据结构，比如有：

- `house of mind`伪造`heap_info`结构体，进而控制`arena`
- 直接打掉`thread_arena`，伪造一个`arena`
- 打掉线程的`tcache`变量
- 修改`pointer_guard`等

## 1-9 __environ

- `GLIBC_TUNABLE`环境变量的设置会控制`ptmalloc_init`的流程，影响很多关键变量的设置，比如`tcache_counts`等。在这里有着设置示例[Tunables (The GNU C Library)](https://www.gnu.org/software/libc/manual/html_node/Tunables.html)。比如`export GLIBC_TUNABLES=glibc.malloc.tcache_count=2`
- 有些特殊的环境变量会泄露出信息，比如`LD_SHOW_AUXV`

## 1-10 other

这里是一些不太好归类的攻击面。有：

- `house of muney`，一种`steal heap`的技巧，通过修改`mmap chunk`的`size`来达成利用
- `exit`的时候会`call tls_call_list`里面的函数指针，但是也要能控制`pointer_guard`
- `exit`的时候会调用一些锁的函数指针，某些博客中称之为`exit_hook`，但是在`2.34`之后这些`hook`被静态函数所代替