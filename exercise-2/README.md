# Fuzzing101 with LibAFL - Part Two

Herein lies a solution to [Exercise 2 from Fuzzing101](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%202) written in Rust, using [LibAFL](https://github.com/AFLplusplus/LibAFL). 

The goal of the exercise is to find [CVE-2009-3895](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3895) and [CVE-2012-2836](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2836) in libexif 0.6.14.

The code housed here has a companion [blog post](https://epi052.gitlab.io/notes-to-self/blog/2021-11-07-fuzzing-101-with-libafl-part-2/) that delves into the different LibAFL components used in the solution.


更新：

改成了0.13.1的LibAFL版本。主要是接口方面有一些变动。

跑了很久也没有在solutions这里得到输出文件，这是为什么呢？暂时不管了。

目前的存在的问题：

client跑起来之后起了ASAN，然后确实找到了几个bug。但是server不知道client找到了bug···一个bug也没有记录到。


其他记录：

InProcessExecutor是调用一个函数

first-seen: Part 1.5
purpose: libfuzzer-like executor, that will simply call a function (i.e. the harness)
why: it’s built for speeeeeeed! should be paired with a restarting event manager for error-handling
