---
layout: post
title: Introduction to the Binary Ninja API
---

As ninjas we value time, and the faster we are able to do something the better. Because of this I try to find tools to expedite my work, and so I have started messing around with [Binary Ninja](https://binary.ninja) from the cool dudes over at [Vector 35](https://vector35.com/) whom I love dearly for the incredible contributions they have made to CTF over the years, my favorite being [Hacking Time](https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/reverse/hacking-time-200/HackingTime_03e852ace386388eb88c39a02f88c773.nes) and [PwnAdventureZ](https://github.com/Vector35/PwnAdventureZ).

While the UI is super sexy and clean, this post is focused on the Python `API` to see how quickly I can build a tool to [Decode ARM64 syscalls](http://arm.ninja/2016/03/07/decoding-syscalls-in-arm64/) based on my last post. Thanks to [Jordan](twitter.com/psifertex) for inviting me to the `BETA` and thanks to Peter who spent a couple hours solving my super novice issues and made this post possible. As always, thanks to [rotlogix](http://www.twitter.com/rotlogix) who continues to inspire me to write these posts.

*note: binary ninja has been lovingly abbrieviated `binja`, and will be referred to as such through the post*

#### Setting up

Typical of my luck, I happened to run into every known and unknown issue while getting set up. Luckily the V35 guys were super helpful getting it straightened out but will document here in case you run into these problems. After getting my copy of the software, (an App Bundle for OS X) I ran into a problem with `homebrew` version of Python 2.7 causing [this issue](https://asciinema.org/a/cjnff76u305mn9ceixtimz4ns) which was later documented [here](https://github.com/Vector35/binaryninja-docs/issues/186) with a temporary solution of simply using the native OS X version of Python:

```
PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python python
```

After this I ran into some errors resulting from a phantom `dylib` on my system causing version mismatches and preventing me from using the `Mach-O` support. You're unlikely to run into this, however it is convient to ensure that your `UI` version matches your `API` version by running: 

```
python -c "import binaryninja; print binaryninja.core_version"
```

After spending some more time with different setups (*and trust me, the homebrew vs native python issue is a smash-laptop-against-a-wall type of problem*) I would recommend you install `virtualenv` for `binja` which is what I am running now and it's working great. The main reason is that `virtualenv` will install a fresh copy of Python without messing with whatever is on your main system, you can get the dependencies installed and run `workon binja` to quickly get back to your environment.

A great guide to follow would be the [Hitchhiker's Guide to Python](http://docs.python-guide.org/en/latest/dev/virtualenvs/)

#### My Setup

Requires `virtualenvwrapper.sh`

- `mkvirtualenv binja`
- `workon binja`

`pip freeze > requirements.txt` yields:

```
appnope==0.1.0
decorator==4.0.9
gnureadline==6.3.3
ipython==4.1.2
ipython-genutils==0.1.0
path.py==8.1.2
pexpect==4.0.1
pickleshare==0.6
ptyprocess==0.5.1
pycrypto==2.6.1
pyreadline==2.1
simplegeneric==0.8.1
traitlets==4.1.0
```

If you put the above into a `requirements.txt` file you can run `pip install -r requirements.txt` **inside** your virtualenv `binja` and have the same setup. I like to run inside `iPython` mostly because of the tab-complete features for quickly accessing objects.

#### Throwing Down

I was given a block of sample code to leverage the Python `API`:

```
from binaryninja import *
import time
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

It should be noted that currently in **`BETA`** the `time.sleep(5)` function is required due the lack of a callback, so there is no way to know when your analysis is complete. While this makes things blazingly fast for larger binaries, adjusting `time.sleep(5)` is annoying and I was warned that this is being solved by implementing proper callback functionality.

Despite this we see that `binja` performs as expected, it finds the symbols: `_main`, `__stack_chk_fail`, `_gets`, `_printf` and displays the start and ending addresses for each basic block associated with each symbol.

#### Binja plugin to decode ARM64 syscalls

Now that we have a basic example working, we are ready to attempt to write a plug-in that decodes ARM64 syscalls - the binary I will be using is `cbd`, Samsung's CP Boot Daemon - a crude algorithm for doing this is:

- Search for supervisor call exceptions in `ARM64`
- Check the `immediate` value being moved to `X8`
- Lookup the value to identify the `syscall`

To do this in `binja` we start similar to the above example, by recursing through each `basic block` but instead of just printing the addresses, we look for all `SVC` instructions. If you don't remember why, go back and read my [post](http://arm.ninja/2016/03/07/decoding-syscalls-in-arm64/) on the subject.

Printing each `basic_block` object in `binja` is easy, and looks like this: 

```
# Isolate a function object, f1:

f1 = bv.functions[0]
f1.basic_blocks

>>> [<block: aarch64@0x400f2c-0x400f44>]
```

and we can get the `basic_block` **start** and **end** address with: 

```
# Isolate a basic_block object, f1b1:
f1b1 = f1.basic_blocks[0]

# Function 1, Basic Block 1:
hex(f1b1.start)
>>> '0x400f2cL'

hex(f1b1.end)
>>> '0x400f44L'
```

So we'll want to generate all instructions between `hex(f1b1.start)` and `hex(f1b1.end)` doing so looks like: 

```
ins = []
start = f1b1.start
end = f1b1.end
while start != end:
  x, size = bv.arch.get_instruction_text(bv.read(start, 4), start)
  ins.append(x)
  start += size
```   

The biggest piece of this to understand is the `get_instruction_text()` function located in `__init__.py`:

![]({{ site.baseurl }}assets/Screen Shot 2016-03-11 at 4.47.35 PM.png)

So `get_instruction_text()` wants `data`, `addr` as its arguments, obviously we know the address for our `basic_block` given above using `f1b1.start`, but to get the data we use the `bv.read()` function which requires `offset` and a `length`. `length` is defined as 4 for `ARM64` due to its fixed 4-byte instruction size. For `x86_64` you would use `16`.

![bv.read()]({{ site.baseurl }}assets/Screen Shot 2016-03-12 at 1.18.47 AM.png)

The instructions returned from the above code: 

```
[['stp', '   ', 'x29', ', ', 'x30', ', ', '[', 'sp', ', #', '-0x10', ']!'], 
['adrp', '   ', 'x0', ', ', '0x473000'], 
['mov', '    ', 'x29', ', ', 'sp'], 
['add', '    ', 'x0', ', ', 'x0', ', ', '#', '0xf50'], 
['bl', '     ', '0x448214'], ['bl', '     ', '0x439c28']]
```

#### Search for supervisor call exceptions in `ARM64`:
A quick-and-dirty algorithm: 

- Loop:
	- Enter `function`
	- Enter `basic_block`
	- Enumerate instructions in `basic_block`
	- Search for `SVC`

Because the instruction has spaces and its list type is not string-y enough for Python, we'll need to do some Pythonic magic (*thanks Oren for helping with this part!*):

##### Putting it all together

```
for func in bv.functions:
     for bb in func.basic_blocks:
     	ins = []
		start = bb.start
		end = bb.end
		while start != end:
    		x, size = bv.arch.get_instruction_text(bv.read(start, 4), start)
    		ins.append(x)
    		start += size
    	for index, item in enumerate(ins):
    		if 'svc' in ''.join(map(str, ins[index])):
        		print "function: %s" % func
        		print "basic block: %s" % bb
        		print "MOV: %s" % ins[index-1]
        		print "SVC: %s" % ins[index]

```

we found **38** `SVC` calls in `cbd` - *WOOHOO* - the above returns: 

```
function: <func: aarch64@0x434268>
basic block: <block: aarch64@0x434268-0x43427c>
MOV: ['mov', '    ', 'x8', ', ', '#', '0xae']
SVC: ['svc', '    ', '#', '0']

function: <func: aarch64@0x4342f8>
basic block: <block: aarch64@0x4342f8-0x43430c>
MOV: ['mov', '    ', 'x8', ', ', '#', '0x50']
SVC: ['svc', '    ', '#', '0']

function: <func: aarch64@0x434310>
basic block: <block: aarch64@0x434310-0x434318>
MOV: ['mov', '    ', 'x8', ', ', '#', '0x5e']
SVC: ['svc', '    ', '#', '0']

function: <func: aarch64@0x434328>
basic block: <block: aarch64@0x434328-0x43433c>
MOV: ['mov', '    ', 'x8', ', ', '#', '0x65']
SVC: ['svc', '    ', '#', '0']

...
```

#### Check the `immediate` value being moved to `X8`


Using this we can see we have addresses for the `func` and address ranges for the `basic_blocks`. This should be all we need to disassemble the functions and look for the `MOV X8, <immediate>` we need to decode the correct `syscall`.

```
for index, item in enumerate(ins):
  count = 0
  if 'svc' in ''.join(map(str, ins[index])):
    for iter in ins[index-1]:
      if count == 5:
        print "syscall: %s @ func: %s " % (iter, func)
        count += 1
```

**Don't judge me**, it's late and the above code "works" by maybe one sense of the defintion. In any case we get the syscalls printed out along with the function it is associated with. I print the function because there is a very large chance that the function is just a handler for the syscall and can be renamed or labeled as such. (ex.: `0x22` is `sys_nice` and `func@0x42a19c` can be labeled `sys_nice_handler`.)

```
syscall: 0x22 @ func: <func: aarch64@0x42a19c>
syscall: 0x4f @ func: <func: aarch64@0x42b57c>
syscall: 0x40 @ func: <func: aarch64@0x434250>
syscall: 0xae @ func: <func: aarch64@0x434268>
syscall: 0x3f @ func: <func: aarch64@0x434280>
syscall: 0x2b @ func: <func: aarch64@0x4342e0>
syscall: 0x50 @ func: <func: aarch64@0x4342f8>
syscall: 0x5e @ func: <func: aarch64@0x434310>
syscall: 0x65 @ func: <func: aarch64@0x434328>
syscall: 0x19 @ func: <func: aarch64@0x434358>
syscall: 0x42 @ func: <func: aarch64@0x434388>
syscall: 0x39 @ func: <func: aarch64@0x4343a0>
syscall: 0x3e @ func: <func: aarch64@0x4343e8>
syscall: 0x84 @ func: <func: aarch64@0x434400>
syscall: 0x51 @ func: <func: aarch64@0x434418>
syscall: 0x92 @ func: <func: aarch64@0x434430>
syscall: 0xde @ func: <func: aarch64@0x434448>
syscall: 0xa7 @ func: <func: aarch64@0x434460>
syscall: 0x60 @ func: <func: aarch64@0x434490>
syscall: 0xe2 @ func: <func: aarch64@0x4344a8>
syscall: 0xd7 @ func: <func: aarch64@0x4344c0>
syscall: 0x5b @ func: <func: aarch64@0x4344f0>
syscall: 0x38 @ func: <func: aarch64@0x434508>
syscall: 0x77 @ func: <func: aarch64@0x434550>
syscall: 0x49 @ func: <func: aarch64@0x434568>
syscall: 0xa6 @ func: <func: aarch64@0x434580>
syscall: 0xac @ func: <func: aarch64@0x439fec>
syscall: 0xce @ func: <func: aarch64@0x43a0a8>
syscall: 0x1d @ func: <func: aarch64@0x43ea1c>
syscall: 0xdc @ func: <func: aarch64@0x449760>
```

#### Lookup value to identify the `syscall`

Now that we have the `<immediate>` we can do a look-up to enumerate which `syscall` it belongs to. The quick-and-dirty way is to just browse to [syscalls.kernelgrok.com](http://syscalls.kernelgrok.com/) and look it up manually.  I'm going to work on cleaning up this code and make it an actual **Binary Ninja Plug-in**, should be uploaded [here](https://github.com/ARMNinja) in the next few days. Binary Ninja is still in `BETA` so I don't feel too rushed to get it out. Any questions as always, [tweet](https://www.twitter.com/theqlabs) me up! 

Thanks for reading.

**@theqlabs**





