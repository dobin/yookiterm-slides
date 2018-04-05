# Resources

A collection of links related to exploit.courses / BFH course. Mostly Linux related. I may reference them in the course. 

Good ones have been tagged by *Recommended*.


# Complete Exploitation Courses

[Open Security Trainings](http://opensecuritytraining.info/Training.html)
* http://opensecuritytraining.info/IntermediateX86.html
* http://opensecuritytraining.info/IntroX86.html
* http://opensecuritytraining.info/IntroX86-64.html
* http://opensecuritytraining.info/Exploits1.html
* http://opensecuritytraining.info/Exploits2.html

[Avatao](https://platform.avatao.com/discover/paths)
* Similar to exploit.courses (interactive shell), just more advanced
* Need to pay
* GDB Intro, Reversing Intro, Exploiting Intro


# Fundamentals 

[GOT and PLT for pwning ](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)
* Article
* 2017
* GOT, PLT, RELRO description, exploiting related
* Recommended

# Linux Exploitation

[return-to-csu: A New Method to Bypass 64-bit Linux ASLR](https://www.blackhat.com/docs/asia-18/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
* 2018
* Doing ROP in .text with CSU section (Does not really bypass ASLR)

[New bypass and protection techniques for ASLR on Linux](http://blog.ptsecurity.com/2018/02/new-bypass-and-protection-techniques.html)
* 2018
* About how ASLR in current Linux Kernels works, in details
* Shows some tiny ASLR weaknesses
* Code: https://github.com/blackzert/aslur


# Heap Exploitation

[Exim Off-by-one RCE: Exploiting CVE-2018-6789 with Fully Mitigations Bypassing](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/)
* Writeup about Exim Remote Exploit
* Lots of heap massage
* No shellcode used
* 2018
* Recommended

[From Heap to RIP](http://blog.frizn.fr/glibc/glibc-heap-to-rip)
* 2018
* attacking ptmalloc2 heap data structures

[GlibC Malloc for Exploiters](https://github.com/yannayl/glibc_malloc_for_exploiters)
* Slides
* Recommended
* 2018
* Heap introduction, exploiting view


# Linux Kernel Exploitation

[Linux-Kernel-Exploit Stack Smashing
](http://tacxingxing.com/2018/02/15/linux-kernel-exploit-stack-smashing/)
* 2018-02-15
* "Principle of kernel stack overflow and the user mode stack overflow are the same, we can use it to hijack control flow and privilge Escalation in Ring 0."
* Writeup


# Linux Defense 

[Linux Kernel Defence Map](https://github.com/a13xp0p0v/linux-kernel-defence-map/blob/master/README.md)
* Overview of Linux Kernel defensive mechanisms


# Fuzzing

[The Art Of Fuzzing](https://www.sec-consult.com/en/blog/2017/11/the-art-of-fuzzing-slides-and-demos/index.html)
* 2018, René Freingruber
* Complete, long introduction in fuzzing (slides, demos)
* A lot of Windows fuzzing (WinAFL)
* Recommended

[fuzzing.io](https://fuzzing.io)
* Material of Richard Johnson, Talos Security, Cisco
* Videos, Presentations, Tools
* State of the art & academic fuzzing material
* Recommended

[IEEE Hacking Without Humans](http://ieeexplore.ieee.org/xpl/mostRecentIssue.jsp?punumber=8013)
* Papers related to DARPA CGC
* 2018

[Google Fuzzer Test Suite](https://github.com/google/fuzzer-test-suite)
* Different vulnerable programs with known bugs
* Github repo

[Go Speed Trace](http://fuzzing.io/Presentations/Go%20Speed%20Tracer%20v2%20-%20rjohnson.pdf)
* Slides, Cisco Talos, Richard Johnson
* About guided fuzzing / tracing / binary translation / hardware tracing
* More about closed source application tracing

[Fuzzing arbitrary functions in ELF binaries](https://blahcat.github.io/2018/03/11/fuzzing-arbitrary-functions-in-elf-binaries/)
* 2018
* Fuzz dedicated functions of a binary with libfuzzer


# General Exploitation

[Unboxing your virtualBox - Niklas Baumstark](https://www.youtube.com/watch?v=fFaWE3jt7qU)
* Virtualbox Exploitation
* Video
* 2018


# Browser Exploitation

[Building a 1-day Exploit for Google Chrome](https://github.com/theori-io/zer0con2018_bpak)
* Presentation, Code
* 2018.03
* JavaScript, Heap


# CTF

[Pwntools Quick Reference Guide](http://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/)
* Short overview of useful pwntools features
* 2016

# Embedded Systems Exploiting

[Exploitation: ARM & Xtensa compared](https://nullcon.net/website/archives/pdf/goa-2018/carel-nullcon-arm-vs-xtensa-exploitation-(final).pdf)
* 2018
* "Stacks, overflows, gadgets, asm, and things"
* Presentation

[Exploitation on ARM-based Systems](https://github.com/sashs/arm_exploitation)
* 2018
* Complete ARM exploitation intro


# Windows

[BugID](https://github.com/SkyLined/BugId)
* Tool
* Check if a crash is exploitable
