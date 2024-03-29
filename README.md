# sys-gdbstub

[![License: MIT](https://img.shields.io/badge/license-MIT-bri)](LICENSE)
![Build Status](https://github.com/mossvr/sys-gdbstub/actions/workflows/build.yml/badge.svg?branch=master)

GDB Stub Sysmodule for the Nintendo Switch.

## Features

+ List running processes
+ Attach/detach from a process
+ Read registers
+ Read/write memory
+ Break/continue
+ List threads and switch between them
+ Breakpoints
+ Single stepping

## Requirements

+ [Atmosphere-NX](https://github.com/Atmosphere-NX/Atmosphere)
+ [devkitPro development environment (for aarch64 gdb)](https://switchbrew.org/wiki/Setting_up_Development_Environment)

## Installation

Download the latest release and extract it to the root of your sdcard. The
sysmodule will be started automatically at the next boot.

## Usage

### Connecting

    (gdb) target extended-remote <your-switch-ip>:10000

### List processes

    (gdb) info os processes
    pid         command
    1           Loader
    2           ProcessMana
    3           sm
    ...

### Attach to process

    (gdb) attach <pid>

