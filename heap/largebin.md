平时接触的很少的largebin

---

下面的是基于**<font color="red">glibc-2.23</font>**的largebin，高版本可能不同，等学到了再来记录。



# largebin

共63个，被分成了6组，每组bin所能容纳的chunk按顺序排成等差数列。

公差分别如下：

> 32 bins of size          64
>
> 16 bins of size        512
>
>   8 bins of size      4096
>
>   4 bins of size    32768
>
>   2 bins of size  262144
>
>   1 bin of size    what's left

32位系统下第一个largebin的chunk最小位512字节，第二个largebin的chunk最小为512+64字节

(处于[512,512+64)之间的chunk都属于第一个largebin)，以此类推。64位也是一样的，1024,1024+64,

[1024,1024+64)属于第一个largebin。

largebin也是采用双链表结构。

为加快检索速度，fd_nextsize和bk_nextsize指针用于指向第一个与自己大小不同的chunk，只有在加入了大小不同的chunk时，这两个指针才会被修改。

多个大小相同的堆块，只有首堆块的fd_nextsize和bk_nextsize会指向其他堆块，后面的堆块的fd_nextsize和bk_nextsize均为0

只有一个bin时，fd_nextsize和bk_nextsize**均指向自身**，可以用来残留**泄露heap地址**。



# largebin attack

以how2heap的代码为例：

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x320);
    malloc(0x20);
    unsigned long *p2 = malloc(0x400);
    malloc(0x20);
    unsigned long *p3 = malloc(0x400);
    malloc(0x20);

    free(p1);
    free(p2);

    void* p4 = malloc(0x90);

    free(p3);

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    malloc(0x90);

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    return 0;
}
```



注意选择低版本的loader，这里patch为2.23的。

执行结果：![image-20240718113226331](largebin\images\image-20240718113226331.png)

调试分析。

开启了-g选项就可以通过 b x 来对源代码的x行下断点进行源码调试。

先重点关注    void* p4 = malloc(0x90);这里

下断点运行到这里，看malloc(0x90)前的堆布局（间隔的三个是用来隔开防止合并的）

![image-20240718114450033](largebin\images\image-20240718114450033.png)



![image-20240718114503464](largebin\images\image-20240718114503464.png)



这里的p1是属于small chunk的(malloc's size <0x3F0 total size <0x400)，p2是属于large chunk的。

然后malloc(0x90)时，其实做了以下几步的事情

- 从unsorted bin中拿出最后一个chunk(P1)
- 把这个chunk(P1)放入small bin中，并标记这个small bin中有空闲的chunk
- 从unsorted bin中拿出最后一个chunk(P2)
- 把这个chunk(P2)放入large bin中，并标记这个large bin中有空闲的chunk
- 现在unsorted bin中为空，**从samll bin的P1中**分隔一个小的chunk，满足请求的P4，并把剩下的chunk(0x330-0xa0)作为"P1_left"**放回unsorted bin中**

看看此时的堆布局

![image-20240718115419844](largebin\images\image-20240718115419844.png)

![image-20240718115434664](largebin\images\image-20240718115434664.png)

从heap的布局确实可以看到在small bin的P1头部切了一块0xa0的下来。

从下面bins的查看发现确实又把切割过后的small bin放回了unsorted bin。



接下来free(P3)，同样的也会先放到unsorted bin过渡。



然后下面就是修改P2的内容。

修改之前P2：

![image-20240718121650114](largebin\images\image-20240718121650114.png)

修改之后，

![image-20240718121729717](largebin\images\image-20240718121729717.png)



有五处内容修改：

- size部分由 0x411 => 0x3F1
- fd部分置空
- bk修改为了 stack_var1_addr - 0x10
- fd_nextsize置空
- bk_nextsize修改为了 stack_var2_addr - 0x20

![image-20240718122344549](largebin\images\image-20240718122344549.png)

这里需要注意的是一个chunk的bk指向的是它的后一个被释放chunk的头指针，

bk_nextsize指向后一个与当前chunk**大小不同的第一个空闲块**的头指针：

有 

- P2->bk->fd = stack_var1
- P2->bk_nextsize->fd_nextsize = stack_var2



接着malloc(0x90)，这里要与第一次申请的一样大小。

与第一次分配的过程也一样，P1_left进small bin，P3进large bin，P1_left分隔0xa0，剩下的再回到unsorted bin

前后堆布局：

![image-20240718123146226](largebin\images\image-20240718123146226.png)



![image-20240718123218170](largebin\images\image-20240718123218170.png)



当然，这里面还有large bin attack的核心部分。

从unsorted bin中拿出P3的时候，首先会判断P3应该归属的bin的类型，这里根据size判断出是large bin。

由于large chunk的数据结构是带有fd_nextsize和bk_nextsize的，且large bin中已经存在了P2这个块，

所以**首先需要进行比较两个large chunk的大小**，并根据大小情况制定两个large chunk的fd_nextsize、bk_nextsize、fd、bk的指针。在2.23的glibc中的malloc.c文件中，比较的过程如下：
![image-20240718123815028](largebin\images\image-20240718123815028.png)

large bin中的chunk如果index相同的情况下，是按照由大到小的顺序排列的。也就是说idex相同的情况下size越小的chunk，越接近large bin。这段代码就是遍历比较P3_size < P2_size的过程，我们只看while循环中的条件即可，这里的条件是当前从unsorted bin中拿出的chunk的size是否小于large bin中前一个被释放chunk的size，如果小于，则执行while循环中的流程。

但由于`P2的size被我们修改成了0x3f0`

P3的size为0x410，P3_size > P2_size，所以不执行while循环中的代码，直接进入接下来的判断

![image-20240718124016027](largebin\images\image-20240718124016027.png)

显然不等，也不执行。

剩下的就是 P3_size > P2_size的情况

![image-20240718124110598](largebin\images\image-20240718124110598.png)

可以看到这里就是我们利用的关键，

glibc的本意是做一个双向链表的插入，

进入else分支后赋值得到：

```c
P3->fd_nextsize = P2;
P3->bk_nextsize = P2->bk_nextsize;
P2->bk_nextsize = P3;
P3->bk_nextsize->fd_nextsize = P3;
```

但是根据我们伪造好的指针，

```c
P2->bk->fd = stack_var1;
P2->bk_nextsize->fd_nextsize = stack_var2;
```

实际的赋值

```c
P3->bk_nextsize = P2->bk_nextsize;
				+
P3->bk_nextsize->fd_nextsize = P3;
                +
P2->bk_nextsize->fd_nextsize = stack_var2;
			   | |
stack_var2的值被修改为了P3的头指针
```

这时，**stack_var2**的值已经修改了，接下来还有对fd,bk指针的操作来修改**stack_var1**

![image-20240718125214980](largebin\images\image-20240718125214980.png)

跟上面一样的，伪造指针赋值后有

stack_var1的值也被修改为了P3的头指针

![image-20240718125429394](largebin\images\image-20240718125429394.png)



所以最后的效果就是可以分别利用fd,bk和fd_nextsize,bk_nexesize将target_addr的值修改为一个chunk的头地址。





总结：

how2heap 中也说了，large bin attack 是未来更深入的利用。现在我们来总结一下利用的条件：

- 可以修改一个 large bin chunk 的 data
- 从 unsorted bin 中来的 large bin chunk 要紧跟在被构造过的 chunk 的后面
- 通过 large bin attack 可以辅助 Tcache Stash Unlink+ 攻击
- 可以修改 _IO_list_all 便于伪造 _IO_FILE 结构体进行 FSOP。