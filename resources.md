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

ELF Intro
* [Executable and Linkable Format 101 - Part 1 Sections and Segments
](http://www.intezer.com/executable-linkable-format-101-part1-sections-segments/)
* [Executable and Linkable Format 101. Part 2: Symbols
](https://www.intezer.com/executable-linkable-format-101-part-2-symbols/)
* [Executable and Linkable Format 101 Part 3: Relocations
](https://www.intezer.com/executable-and-linkable-format-101-part-3-relocations/)


[Exploiting Cheat sheet](https://pbs.twimg.com/media/DaCPl0QW0AAsL1E.jpg:large)
* Picture
* Cheatsheet

[file descriptors](https://pbs.twimg.com/media/DaEj6zWVwAEl9eH.jpg)
* Picture
* File Descriptors in Linux

[JULIA'S DRAWINGS](https://drawings.jvns.ca/)
* Simple drawings about linux fundamentals 
* Recommended


# Linux Exploitation

[Bypass ASLR+NX Part 1](http://intx0x80.blogspot.ch/2018/04/bypass-aslrnx-part-1.html)
* 2018
* Doing local exploit with ASLR+DEP, via `strcpy()` the string `sh` to .bss with ROP, then `system()` it
* Recommended

[return-to-csu: A New Method to Bypass 64-bit Linux ASLR](https://www.blackhat.com/docs/asia-18/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
* 2018
* Doing ROP in .text with CSU section (Does not really bypass ASLR)

[New bypass and protection techniques for ASLR on Linux](http://blog.ptsecurity.com/2018/02/new-bypass-and-protection-techniques.html)
* 2018
* About how ASLR in current Linux Kernels works, in details
* Shows some tiny ASLR weaknesses
* Code: https://github.com/blackzert/aslur

[ROPping to Victory](https://jmpesp.me/rop-emporium-ret2win-with-radare-and-pwntools/)
* 2018
* ROP guide with radare
* Very simple buffer overflow, which calls a predefined function

[Binary Exploitation ELI5– Part 1
](https://medium.com/@danielabloom/binary-exploitation-eli5-part-1-9bc23855a3d8)
* Some intro to computers, memory model
* 2018
* Simple intro


# Heap Exploitation

[Exim Off-by-one RCE: Exploiting CVE-2018-6789 with Fully Mitigations Bypassing](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/)
* Writeup about Exim Remote Exploit
* Lots of heap massage
* No shellcode used
* 2018
* Recommended
* Exploit Writeup: [My PoC walk through for CVE-2018–6789
](https://medium.com/@straightblast426/my-poc-walk-through-for-cve-2018-6789-2e402e4ff588)

[From Heap to RIP](http://blog.frizn.fr/glibc/glibc-heap-to-rip)
* 2018
* attacking ptmalloc2 heap data structures

[GlibC Malloc for Exploiters](https://github.com/yannayl/glibc_malloc_for_exploiters)
* Slides
* Recommended
* 2018
* Heap introduction, exploiting view

x86 exploitation - heap overflows
* 2015
* Inter-chunk overflows and similar
* [House Of Spirit](https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/)
* [House Of Lore](https://gbmaster.wordpress.com/2015/07/16/x86-exploitation-101-house-of-lore-people-and-traditions/)
* [House Of Force](https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/)
* [House Of Mind](https://gbmaster.wordpress.com/2015/06/15/x86-exploitation-101-house-of-mind-undead-and-loving-it/)

[Heap Viewer](https://github.com/danigargu/heap-viewer)
* Tool for IDA 
* ptmalloc2 heap viewer


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


# VM Exploitation

[Unboxing your virtualBox - Niklas Baumstark](https://www.youtube.com/watch?v=fFaWE3jt7qU)
* Virtualbox Exploitation
* Video
* 2018

[A bunch of Red Pills: VMware Escapes]https://keenlab.tencent.com/en/2018/04/23/A-bunch-of-Red-Pills-VMware-Escapes/
* List of several VMWare exploits (guest to host)
* 2018
* Good overview


# Browser Exploitation

[Building a 1-day Exploit for Google Chrome](https://github.com/theori-io/zer0con2018_bpak)
* Presentation, Code
* 2018.03
* JavaScript, Heap

[How to kill a (Fire)fox](http://blogs.360.cn/blog/how-to-kill-a-firefox-en/)
* 2018, pwn2own bug
* Heap exploit

[CVE-2017-0236 analysis](http://math1as.com/2018/04/10/CVE-2017-0236-analysis/)
* UAF in Edge analysis, windbg
* 2018

[Attacking JavaScript Engines](http://phrack.org/papers/attacking_javascript_engines.html)
* 2016 
* A case study of JavaScriptCore and CVE-2016-4622

[Root cause analysis of the latest Internet Explorer zero day – CVE-2018-8174](https://securelist.com/root-cause-analysis-of-cve-2018-8174/85486/)
* 2018 
* UAF
* Short writeup



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

[Windows 10 mitigations improvements](https://www.blackhat.com/docs/us-16/materials/us-16-Weston-Windows-10-Mitigation-Improvements.pdf)
* Anti exploit mitigations in windows 10
* Lots of statistics, data, techniques
* 2016
* Recommended

[Breaking CFI: Exploiting CVE-2015-5122 using COOP.](https://perception-point.io/2018/04/11/breaking-cfi-cve-2015-5122-coop/)
* New technique to bypass some CFI implementations

[Exploiting CVE-2018-1038 - Total Meltdown](https://blog.xpnsec.com/total-meltdown-cve-2018-1038/)
* Win7 Fail Meltdown Patch exploit 
* Writing an easy Kernel exploit


# Shellcoding 

[How to write a (Linux x86) egg hunter shellcode](https://adriancitu.com/2015/10/05/how-to-write-an-egg-hunter-shellcode/)
* 2018 
* Short article about egghunting (finding most of shellcode somewhere in memory)


# Debugging

[C++ links: debugging: articles, documentation, software, and talks](https://github.com/MattPD/cpplinks/blob/master/debugging.md)
* List of resources
* Many many links


# Reverse Engineering 

[Reverse Engineering x64 for Beginners – Linux](http://niiconsulting.com/checkmate/2018/04/reverse-engineering-x64-for-beginners-linux/)
* 2018 
* Intro into reversing with GDB

[Reverse Engineering With Radare2 – Part 3](https://insinuator.net/2016/10/reverse-engineering-with-radare2-part-3/)
* 2018
* Using Radare to reverse

[BOLO: Reverse Engineering — Part 1 (Basic Programming Concepts)](https://medium.com/bugbountywriteup/bolo-reverse-engineering-part-1-basic-programming-concepts-f88b233c63b7)
* 2018
* How basic functions look in assembly


