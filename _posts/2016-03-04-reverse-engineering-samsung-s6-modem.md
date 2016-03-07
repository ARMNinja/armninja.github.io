---
layout: post
title: Reverse Engineering Samsung S6 Modem
---

So I was a little late to the game, and just got my hands on a Samsung Galaxy S6, specifically the `SM-G920F` which will be the topic of discussion in this post. I am quite curious as to understanding the structure of the device's `modem.bin` file. While I haven't been able to get a de-obfuscated/decrypted version of `modem.bin` yet, hopefully this post will help others quickly get up-to-speed and assist in the pursuit of one. 

Anyone interested in helping or contributing can hit me with the Tweets `@theqlabs` or submit a PR.

**TL;DR - i do not have a decrypted modem.bin yet, but here are all my notes, send help. <3**

# Obtaining Files
- Download **Samsung** [SM-G920F](http://www.sammobile.com) **Galaxy S6** Firmware

# Extracting Files
I had some issues using `UnZip 5.52` on OS X (PK compat. error), so instead I used `UnZip 6.00` on Ubuntu 15.04. 

```
unzip <firmware.zip>
mv <firmware.tar.md5> <firmware.tar>
tar xvf <firmware.tar>
```

You should end up with something like:

```
boot.img
cache.img
cm.bin
hidden.img
modem.bin
recovery.img
sboot.bin
system.img
```


# Deconstructing ``modem.bin``

**Endianness**: Most of what we will be seeing in `modem.bin` is comprised of Little-Endian format. That is, the Most Significant Byte is located at the highest memory address. **Example**: If you look at `SIZE` of `BOOT` below, the bytes are ordered as `48 2B 00 00` but read and sent as `0x2B48` dropping the `00`s as you would in decimal for anything before a non-zero number.
		

### TOC[0] = TOC

Opening `modem.bin` in a Hex Editor gives some immediate insight into what is happening with this file.

The first `0x200` bytes are called the `TOC`, I am going to make a slightly ambitious guess that this stands for `Table of Contents`. Its function is to provide information about the file itself including all [5] of its sections, namely: `TOC`, `BOOT`, `MAIN`, `NV` and `OFFSET`, as well as providing an index into these sections.
 
![header]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 3.22.21 PM.png)

 While the above screen shot shows only addresses `0000h-0090h` the remaining bytes are all zero-padded `0x200` bytes in total.


### TOC[1] = BOOT

If you want to isolate the `BOOT` section of the file you would do so by calculating the offsets based on the `SIZE` parameter from the header file. So for our example it would look like the following: 

	dd if=modem.bin bs=1 skip=512 count=11080 of=modem.bin_boot
	
	# calculated by using the 0x200 byte offset in decimal.
	skip=512
	 
	# calculated by using the 0x2B48 byte SIZE of BOOT in decimal.
	count=11080

![]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 4.51.03 PM.png)

| Address | Bytes | Length | Description | Value |
| --- | --- | --- | --- | --- |
| `0020`-`0028` | **`42 4F 4F 54`** | 4-8 Bytes | `NAME` of Section | BOOT |
| `0028`-`002C` | **`00 00 00 00`** | 4 Bytes | Unused  | |
| `002C`-`0030` | **`00 02 00 00`** | 4 Bytes | Unknown |
| `0030`-`0034` | **`00 00 00 00`** | 4 Bytes | Unknown | 
| `0034`-`0038` | **`48 2B 00 00`** | 4 Bytes | `SIZE` of `BOOT` | `0x2B48` bytes |
| `0038`-`003C` | **`45 03 27 5E`** | 4 Bytes | `CRC` of `BOOT` | `0x5E270345` |
| `003C`-`0040` | **`00 00 00 00`** | 4 Bytes | `INDEX` | Index into `TOC` |



### TOC[2] = MAIN
Similar to `BOOT` you would isolate `MAIN` with the following `dd` command:

	dd if=modem.bin bs=1 skip=11592 count=40394816 of=modem.bin_main

![MAIN]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 3.21.20 PM.png)

| Address | Bytes | Length | Description | Value |
| --- | --- | --- | --- | --- |
| `0040` - `0048` | **`4D 41 49 4E`** | 4-8 Bytes | `NAME` of Section | MAIN |
| `0048` - `004C` | **`00 00 00 00`** | 4 Bytes | Unused  | |
| `004C` - `0050` | **`60 2D 00 00`** | 4 Bytes | `VERSION`* | `0x2D60` 1.16.16 |
| `0050` - `0054` | **`00 00 00 40`** | 4 Bytes | Unknown | 
| `0054` - `0058` | **`40 60 68 02`** | 4 Bytes | `SIZE` of `MAIN` | `0x2686040` or 40,394,816 bytes or ~40MB |
| `0058` - `005C` | **`24 BD DF 93`** | 4 Bytes | `CRC` of `MAIN` | `0x93DFBD24` |
| `005C` - `0060` | **`02 00 00 00`** | 4 Bytes | `INDEX` | Has to do with index into `TOC` |

`*` - `VERSION` is a guess based on analyzing multiple firmwares, seen both `0x2D00` and `0x2D60`. Will confirm, should be able to reverse `cbd` `prepare_boot_args` or related functions to ensure the above is correct.

### TOC[3] = NV

![]({{ site.baseurl }}assets/Screen Shot 2016-03-01 at 12.29.54 AM.png)

| Address | Bytes | Length | Description | Value |
| --- | --- | --- | --- | --- |
| `0060` - `0068` | **`4E 56 00 00`** | 4-8 Bytes | `NAME` of Section | NV |
| `0068` - `006C` | **`00 00 00 00`** | 4 Bytes | Unused  | |
| `006C` - `0070` | **`00 00 00 00`** | 4 Bytes | Unknown |
| `0070` - `0074` | **`00 00 EE 47`** | 4 Bytes | Unknown | 
| `0074` - `0078` | **`00 00 10 00`** | 4 Bytes | `SIZE` of `NV` | `0x2B48` bytes |
| `0078` - `007C` | **`00 00 00 00`** | 4 Bytes | `CRC` of `NV` | N/A |
| `007C` - `0080` | **`03 00 00 00`** | 4 Bytes | `INDEX` | Has to do with index into `TOC` |


### TOC[4] = OFFSET
I have never seen `cbd` process or send this section, so I'm assuming its use is local to the `modem.bin` file and not to the CP. Perhaps the `BOOT` is using it in some way? 

# Decoding `BOOT`
So you may have noticed some patterns while looking at the `BOOT` code, in our example located from `0200-02D48h` and in case you didn't I'm going to show you a trick I learned from the **Practical Reverse Engineering** [book](http://smile.amazon.com/dp/1118787315) by Dang et al. As they so correctly state: 

> The ability to recognize instruction boundaries in a seemingly random blob of data is important. Maybe you will appreciate it later.

Also, say **Dang et al.** out loud. Ha!

Let's review a chunk of `BOOT`:

![]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 8.41.40 PM.png)

**TL;DR** - These are ARM instructions and we're about to disassemble the sh*t out of them.

Looking at this blob, it's easy to notice a pattern. Almost every `4th byte` ends in `0xE*` - as it turns out, ARM branch instructions use the Most Significant Bits for a conditional code. These [codes](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0204j/Chdhcfbc.html) control the execution of instructions and are typically based on the flags set in the [Application Program Status Registers](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0413d/ch02s02s02.html) or `APSR`. So if you want to tell an instruction to Always Execute, you would use the `AL` condition which is `1110b` or `0xE`. If you have any experience with crackmes this is analogous to switching the `Z` or Zero Flag when you wanted to alter the state of a conditional JMP (x86) or B (ARM).

**TODO**: Reversing `BOOT` will be part of a later post.

# CP Boot Process
The following is what I know based on crashing the modem many times, reversing `cbd` and `BOOT`

	cbd	 # CP Boot Daemon lives in /sbin on the device
	CP 	 # Cell Processor or Modem
	AP	 # Application Processor, where Android OS lives
	BOOT	 # BOOT section of the modem.bin

### `/dev/umts_boot0`
Opened by `rild` used for most I/O involving CP boot chain.

	misc_ioctl:
		IOCTL_MODEM_ON
		IOCTL_MODEM_BOOT_ON
		IOCTL_MODEM_DL_START	 # Starts `mem_start_download`
		IOCTL_MODEM_SET_TX_LINK	 # Sets Boot Link / Main Link
		IOCTL_MODEM_FW_UPDATE	 # Called after stages are sent to CP
		IOCTL_MODEM_BOOT_OFF	 # Sent after Stage 3 is sent to CP
		IOCTL_MODEM_BOOT_DONE	 # Final IOCTL for CP boot chain

### `start_shannon333_boot`
...

### `shannon_normal_boot` 
`LLI STATUS mount`

### `prepare_boot_args`
...

![dmsg]({{ site.baseurl }}assets/Screen Shot 2016-02-28 at 2.21.46 PM.png)


###  `mem_start_download` 
Triggered by `IOCTL_MODEM_DL_START` which grabs the `BOOT` section of `modem.bin` and sends it to the CP to start the boot code. The code appears to come from `link_device_bootdump.c` in the Android kernel.

`magic == 0x424F4F54` or `BOOT`

![]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 4.38.10 PM.png)

### `std_dl_send_bin`

Sends parsed `modem.bin` to CP RAM via `BOOT` code. I'm thinking the `CMD=` are private IOCTL command IDs.

#### Stage 1: `0x200` bytes header
![]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 11.48.04 PM.png)

#### Stage 2: `0x2686040` bytes `MAIN`
![]({{ site.baseurl }}assets/Screen Shot 2016-02-29 at 11.48.20 PM.png)

#### Checks `CRC` for `MAIN`
I'm guessing it sends the `MAIN` `CRC` to the `BOOT` code to verify

![]({{ site.baseurl }}assets/Screen Shot 2016-02-11 at 8.40.31 PM.png)

#### Stage 3: `0x100000` bytes of `NVRAM`
![]({{ site.baseurl }}assets/Screen Shot 2016-03-01 at 12.02.43 AM.png)


### `check_factory_log_path`
Set to `/sdcard/log`/ annoyingly the `SM-G920F` does not have an SD CARD slot so uses a shitty Virtual SD daemon that does not appear to work correctly because I can not get anything saved into the directory. Will work on a way to set this, should be fairly simple. 


### `std_udl_req_resp`
I'm not sure why `cbd` calls these functions, but called before `std_dl_send_bin`


# Service Mode Functions

There are many service mode functions that Samsung kindly provides that will help during reversing.

	# Enable CP Debugging
	am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://66336
	
	<device resets>

	# Enable CP RAMDUMP
	am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://9090
	
	<device resets>
	
	# Cause CP RAMDUMP
	am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://CP_RAMDUMP
	
	# SysDump, Copy to SD Card
	am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://9900


Working on writing up my notes on reversing `CP Boot Daemon` and `BOOT`, hopefully will post soon. I still need to figure out how to organize this damn thing. Hopefully this helps those interested jump-start their research, and feel free to reach out via [Twitter](http://twitter.com/theqlabs).
