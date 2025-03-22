[pwn初学者的进阶（四）：SROP - zyleo's blog (liuliuliuzy.github.io)](https://liuliuliuzy.github.io/2021-11-01-srop学习/)

当然还有ctf-wiki的对应内容。



主要是感觉syscall学的很浅，或者是根本不会。。。 所以得把syscall好好学一学再来看这个SROP



2024年7月5日

今天大致看了看，原理大致明白。

主要就是这张图

![image-20240705171857171](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\SROP\images\image-20240705171857171.png)

我的理解就是，

内核执行完sigreturn系统调用后，会把这个SigFrame里面的值依次pop给寄存器。

核心还是控制寄存器。

至于那道例题：[ciscn_2019_es_7](https://buuoj.cn/challenges#ciscn_2019_es_7)

唯一一个困惑的点是为什么不用覆盖ebp就能控制指令流？

![image-20240705172034232](D:\N0zoM1z0\CyberSpaceSecurity\Pwn\stack\SROP\images\image-20240705172034232.png)



上面对应的栈的offset，和其他的系统调用基本都懂，只是不覆盖ebp属实没整明白。。。