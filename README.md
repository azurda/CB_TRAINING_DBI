# Requirements
- A working VirtualBox copy installed on the device.
- At least 50Gb disk space available on the device, and a minimum of 4Gb of RAM.
- Basic Python2/3 knowledge
- Understanding Javascript
- A brain!

# SSH Access

__Credentials will be posted here soon__

# VirtualBox VM Image

Please use this link to download the VM Image. 

https://drive.google.com/open?id=1V6ga9Ufzu20mD3_1K8iOdbGxIJl8BC5R

You can import following these steps:



# Timetable

## [1 hour] What is DBI? What is it useful for? 

- DBI frameworks
- What is DBI?
- Frida internals.

During the beginning of the training, we will focus on what DBI is. We will see the different frameworks that are available for binary instrumentation, and also the reason why we will choose Frida for the training. We will also comment on tools already created on top of Frida and a basics of its internals.

## [15 MINUTE BREAK] 

## [1 hour] General introduction to malware, common things to be aware of (registry keys, persistence, networking...) and useful APIs to inspect.

- Introduction to malware, types of malware
- Common persistence techniques
- Anti-virtualization checks
- Useful APIs for inspection

We will learn the basics of Windows malware. Although we won’t enter into low-level stuff (disassembly), we will learn about common persistence techniques, useful windows APIs to inspect, and anti-virtualization techniques in order to get the big picture. With this information, we will know what APIs we should inspect while doing instrumentation. 

## [15 MINUTE BREAK]

## [1 hour and 30 minutes] Learn the basics of the Frida framework, create our very first instrumentation script.

- Basics of the Frida framework, API basics
- Creating simple C programs for inspection, knowing the source
- Create a basic Frida script using Python bindings
- Make use of different Frida features to learn how to use the framework.

From this part of the training, all the content will be practical. We will learn to use the FRIDA framework to create instrumentation scripts. For the beginning, we will use small programs that allows us to understand how the framework works and its capabilities. The basic API of the framework will be explained, 

## [Lunch break] 

## [1 hour and 30 minutes] Instrumenting a real application

- Creation of our first real-world instrumentation script
- Examine a non-malicious sample without source-code access.
- Use of DBI to figure out anti-virtualization techniques built by this program. 
  - Implement API inspection
	- Logging implementation
	- Arguments and return values implementation

For this part of the training, we will examine a real binary file. It contains techniques used by malware to evade execution in sandboxed environments, These checks are usually implemented in real malware.

We will learn how to find these checks by the usage of Binary Instrumentation: Information retrieval through API inspection and static analysis, using binary instrumentation to get run-time information. Once we have enough data, we will patch these routines.
retrieve information from them. 

##  [15 MINUTE BREAK]

## [1 hour and 30 minutes] Integrate child-gating into our script

- Creation of child-process-following skeleton
- Extend API inspection
- Testing our API inspection on real malware

By itself, we are not able to track children processes. There are different ways to attach to a child process, however the framework allows its own way of attaching to child processes properly without losing information. During this part of the training, we will create an skeleton that allows us to follow child processes. Also, we will augment the inspection of interesting API calls in order to instrument malware and gain information on its behavior. During this part of the training, we will use real malware samples inside a controlled environment (Virtual machine) 
