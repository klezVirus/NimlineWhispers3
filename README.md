```
             %              ..%%%%%#               %/.                  
           /%%%%%,.%%%%%%%%%%%%%%%%%%%%%%%%%%%%.%%%%%%                  
       . #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.               
  %%*.%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ,%%         
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.         
    #%%%%%%%%%%%%%%.                         %%%%%%%%%%%%%%%%           
      %%%%%%%(                                     %%%%%%%%%            
    &   %%#                                           .%%  ..           
     &&.                          .                     . #&            
      &&&&.               . %&&&&&&&&.                 &&&&             
       &&&&&&&.. .   . (&&&&&&&&&&&&&&&&&%. .     .&&&&&&&              
       .%&&&&&&&&&&&&&&&&&&&&& ___  &&&&&&&&&&&&&&&&&&&&& 
         #&&&&&&&&&&&&&&&&&&& |__ \  &&&&&&&&&&&&&&&&&&&
           ,&&&&&&&&&&&&&&&&&    ) | &&&&&&&&&&&&&&&&&
               &&&&&&&&&&&&&&   / /  &&&&&&&&&&&&&&
                   &&&&&&&&&&  / /_  &&&&&&&&&&
                          %&& |____| &&.                                  
                                            NimlineWhispers2
                                            @ajpc500 2021
```

# NimlineWhispers2 #

Originally inspired by Outflank's [InlineWhispers](https://github.com/outflanknl/InlineWhispers) tool, `NimlineWhispers2` processes output from [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) to provide compatible inline assembly for use in Nim projects.

As with the original `NimlineWhispers`, this project also parses the `SysWhispers2` header file output to include function return types and arguments in the outputted inline assembly. Everything is then output into a single Nim file including an `emit` block with the SysWhispers2 methods, plus the defined functions. 

> NOTE: NimlineWhispers 1 can be found [here](https://github.com/ajpc500/NimlineWhispers).

### How do I set this up? ###

 * Clone this repository including the forked [SysWhispers2](https://github.com/ajpc500/SysWhispers2) sub module.
    * `git clone --recurse-submodules https://github.com/ajpc500/NimlineWhispers2.git `
 * Update which functions you required in `functions.txt`.
 * Run `python3 NimlineWhispers2.py` (additional flags listed below) to generate the inline assembly (`syscalls.nim`) file - example in the repo.
 * Add `include syscalls` to your Nim project.

An example of integrating NimlineWhispers2 output with your project can be seen in this [repo](https://github.com/ajpc500/NimExamples/tree/main/src/SysWhispers2).

### Randomised Function Names (same functionality as NW1) ###

To evade detection based on the presence of function names in our Nim executables (as outlined in [@ShitSecure](https://twitter.com/ShitSecure)'s blog [here](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)), NimlineWhispers2 can be run with a `--randomise` flag, as follows:

```
python3 .\NimlineWhispers2.py --randomise --nobanner
[i] Function filter file "functions.txt" contains 6 functions.

[i] Using SysWhispers2 to generate asm stubs...
Complete! Files written to:
        nimlinewhispers.h
        nimlinewhispers.c
        nimlinewhispersstubs.asm

[i] Found return types for 6 functions.

[i] Producing randomised function mapping...
        NtResumeThread -> vWhUCQWffAEdMboE
        NtAllocateVirtualMemory -> SIitcDuyPGMirHPr
        NtClose -> uWZzTmdnlNmvteiL
        NtCreateThreadEx -> PDoWbNOwYbDDAcmW
        NtOpenProcess -> vWfwKlChxKZOutiX
        NtWriteVirtualMemory -> wItyVDPJWcFUqTNK

[+] Success! Outputted to syscalls.nim
```

For ease of integration, the mapping shown in the command-line is added as a comment in the outputted `syscalls.nim` file (just above the functions and below the SW2 methods). As below (including the first function to demonstrate the output):

```
...

# NtResumeThread -> vWhUCQWffAEdMboE
# NtAllocateVirtualMemory -> SIitcDuyPGMirHPr
# NtClose -> uWZzTmdnlNmvteiL
# NtCreateThreadEx -> PDoWbNOwYbDDAcmW
# NtOpenProcess -> vWfwKlChxKZOutiX
# NtWriteVirtualMemory -> wItyVDPJWcFUqTNK

proc vWhUCQWffAEdMboE*(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov [rsp +8], rcx 
...
```
Notably your function definitions such as the below will need to be updated with the randomised names too.

```
EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);
```
Should become:

```
EXTERN_C NTSTATUS sjGfpzWwEqIMryMW(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);
```

`syscalls_rand.nim` is included as an example output of this randomisation function.

### Limitations ###

 * 64-bit only.

### Credits ###

 * [Cas van Cooten](https://twitter.com/chvancooten) and [yamakadi](https://github.com/yamakadi) for posing and then [answering](https://gist.github.com/chvancooten/083dbdfd4a10261ee8dfecb4caf07e6c#gistcomment-3989360) how SW2 output could be used in Nim projects, which I've simply codified😁
 * This tool uses [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) to generate syscall stubs which are then processed for Nim, huge props to [@Jackson_T](https://twitter.com/Jackson_T) for `SysWhispers2`.
 * FalconForce's [SysWhispers2BOF](https://github.com/FalconForceTeam/SysWhispers2BOF) from which I borrowed several helper functions.
 * All people credited for [SysWhispers](https://github.com/jthuraisamy/SysWhispers#credits) and [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2#credits)
 * @Outflank and @\_DaWouw for InlineWhispers
 * @byt3bl33d3r for his incredibly informative [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repository

