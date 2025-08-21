The sdinfo extension module
===============================

This is a [crash utility] extension module to display Linux kernel's scsi disk
information.  

Getting Started
---------------

To build the module from the top-level `crash-<version>` directory, enter:

    $ cp <path-to>/scsi.c scsi.mk extensions
    $ make extensions

To load the module's commands to a running crash session, enter:

    crash> extend <path-to>/scsi.so

To show the module's commands, enter:

    crash> extend
    SHARED OBJECT            COMMANDS
    <path-to>/scsi.so         sdinfo

Help Pages
----------

The module has only a command: [`sdfindo`](#sdinfo-command).

### `sdinfo` command

```
NAME
  sdinfo - dump scsi device information

SYNOPSIS
  sdinfo [-c device_addr] [-C] [-q device_addr] [-Q] [-d] [-s] [-t] 

DESCRIPTION
  This command dumps the scsi device information.

    -c [device_addr]
                   show device SCSI commands
    -C
                   show SCSI commands for all devices (may take a while)",
    -q [device_addr]
                   show device IO request, SCSI commands for request_queue
    -Q
                  show all devices IO request, SCSI commands for request_queue (may take a while)
    -d
                   show all scsi device info
    -s
                   show all scsi hosts info
    -t
                   show all scsi targets info
```

Related Links
-------------

- [crash utility] (https://crash-utility.github.io/)

[1]: https://crash-utility.github.io/