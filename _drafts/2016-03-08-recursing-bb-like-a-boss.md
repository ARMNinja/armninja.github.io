---
layout: post
title: Recursing Basic Blocks like a Boss
---

`TODO: re-write this, sounds like shit`

As ninjas we value time, and the faster we are able to do something the better. Because of this I try to find tools to expedite my work, and so I have started messing around with [Binary Ninja](https://binary.ninja) from the cool dudes over at [Vector 35](https://vector35.com/) whom I love dearly for the incredible contributions they have made to CTF over the years, my favorite being [Hacking Time](https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/reverse/hacking-time-200/HackingTime_03e852ace386388eb88c39a02f88c773.nes) and [PwnAdventureZ](https://github.com/Vector35/PwnAdventureZ).

While the UI is super sexy and clean, this post is focused on the Python `API` to see how quickly I can build a tool to [Decode ARM64 syscalls](http://arm.ninja/2016/03/07/decoding-syscalls-in-arm64/) based on my last post. Thanks to [Jordan](twitter.com/psifertex) for inviting me to the `BETA` and thanks to Peter who spent a couple hours solving my super novice issues and made this post possible.

*note: binary ninja has been lovingly abbrieviated `binja`, which i love, and will refer to it as such through the post*

#### Setting up

Typical of my luck, I happened to run into every known and unknown issue while getting set up. Luckily the V35 guys were super helpful getting it straightened out but will document here in case you run into these problems. After getting my copy of the software, (an App Bundle for OS X) I ran into a problem with `homebrew` version of Python 2.7 causing [this issue](https://asciinema.org/a/cjnff76u305mn9ceixtimz4ns) which was later documented [here](https://github.com/Vector35/binaryninja-docs/issues/186) with a temporary solution of simply using the native OS X version of Python:

```
PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python python
```

After this I ran into some errors resulting from a phantom `dylib` on my system causing version mismatches and preventing me from using the `Mach-O` support. You're unlikely to run into this, however it is convient to ensure that your `UI` version matches your `API` version by running: 

```
python -c "import binaryninja; print binaryninja.core_version"
```

#### Throwing Down

I was given a block of sample code to leverage the Python `API`:

```
from binaryninja import *
bv = BinaryViewType['Mach-O'].open("stack1")
bv.update_analysis()
time.sleep(5)
for func in bv.functions:
   print func.symbol.name
   for block in func.basic_blocks:
      print hex(block.start), hex(block.end)
```

which results in the following for [Gera's](https://github.com/deadbits/InsecureProgramming) `stack1` binary: 

```
_main
0x100000ea0L 0x100000ef3L
0x100000f04L 0x100000f1eL
0x100000ef3L 0x100000f04L
0x100000f2aL 0x100000f36L
0x100000f1eL 0x100000f2aL
___stack_chk_fail
0x100000f30L 0x100000f36L
_gets
0x100000f36L 0x100000f3cL
_printf
0x100000f3cL 0x100000f42L
```

It should be noted that currently in `BETA` the `time.sleep(5)` function is required due the lack of a callback function, so there is no way to know when your analysis is complete. While this makes things blazingly fast for larger binaries, adjusting `time.sleep(5)` is annoying and I was warned that this is being solved by implementing callback functionality.

Despite this we see that `binja` performs as expected, it finds the symbols: `_main`, `__stack_chk_fail`, `_gets`, `_printf` and displays the start and ending addresses for each basic block associated with each symbol.

#### Binja plugin to decode ARM64 syscalls

Now that we have a basic example working, we are ready to attempt to write a plug-in that decodes ARM64 syscalls, a crude algorithm for doing this is:

- Search for supervisor call exceptions in `ARM64`
- Check the `immediate` value being moved to `X8`
- Lookup the value to identify the `syscall`

`TODO: To do any type of lookup, i'll need a list of ARM64 syscalls in code`

To do this in `binja` we start similar to the above example, by recursing through each `basic block` but instead of just printing the addresses, we look for the instructions `SVC 0` or bytecode: `00 11 22 33`.



