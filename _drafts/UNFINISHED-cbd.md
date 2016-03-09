---
layout: post
title: CP Boot Daemon
---

Notes regarding the operation of `CP Boot Daemon` located at: `/sbin/cbd`. The *init* on my `SM-G920F` looks like:
![]({{ site.baseurl }}assets/Screen Shot 2016-02-09 at 10.53.39 PM.png)

**TODO: add screen shot of cbd help output**

The function of `cbd` is to perform early boot operations for the Cell Processor (CP) including parsing `modem.bin`, sending `BOOT` to the CP, validating `MAIN` CRC checksum, and numerous other operations as detailed in the Functions and IOCTLs table below.

# Functions and IOCTLs

Fill this table in from cbd.idb database notes:

| Name | IOCTL |
| --- | --- |
|`start_shannon_boot` | <...> |
| ... | ... |
