GoPayloadDropper is a tool to quickly generate evasive shellcode launchers based on launcher templates. I wrote this because running individual crypters, remembering keys/encryption methods, and downloading 

*Note: This is an early version of this tool, and is 100% expiremental. Use caution!*

## Overview
The tool is intended to generate an encrypted shellcode file and a corresponding launcher that does the following:
- Accesses the shellcode download URL or TXT record provided during generation
- Downloads shellcode
- Decrypts shellcode using method and key provided during generation
- Executes the shellcode using the method provided

The objective here is to combine the encryption, download, decryption, and execution of the shellcode into one templatized, modular codebase. 

## Usage 

## How Does it Work?
There are two primary pieces of code: the Generator and the Template. The Generator is what is ran to produce the encrypted shellcode and configure the launcher. The Template is the 'proto-launcher' that contains all types of code for each of the stages mentioned in 'Overview'. This is populated, cut-up, and randomized by the Generator, then the Launcher/Dropper is built based on the Template .go file.

### Encryption/Decryption Functions
Encryption functions are defined in the Generator, and are individual Golang functions. Decryption functions are **all** listed in the Template, but only the relevant function is kept in the final Launcher/Dropper build.

### Download Functions
The download functions (used by the Launcher to actually pull the shellcode into memory) are all listed within the Template, but only the relevant function is kept in the final Launcher build.

### Execution Functions
These define how the plaintext shellcode is executed. These are all functions within the Template, but only the relevant function is kept in the final Launcher build.

### Randomization
There's two types of randomization that occurs during the Launcher generation:
1. A randomization token is generated and inserted into the launcher, which is used to ensure that the hash of your final Launcher binary is always dynamic. **This always occurs**.
2. Selective randomization of variable names occurs if the 'randomize' command line flag is set to 'true'. This is to add an extra layer of evasiveness.

## On Evasiveness
The entire purpose of this tool is to aid in evading AV/EDR, and it does pretty well at that. But it's not perfect, and depends highly on the configuration options you feed it. It's not so hard to get shellcode launched when an AV/EDR is present, but you still need to keep the following in mind:
- What is the reputation of the domain you're pulling your encrypted shellcode from?
- What do your postex activities look like? Are they also evasive?
- How are you delivering a fat Golang binary to your target?

Check out the VirusTotal results for a few pieces of shellcode I ran:

Meterpreter

Covenant

## TODO
- Add encryption of the download source and decryption at runtime
- Add option to pull key from a download source
- Finish the existing crypters
- Implement authenticity and integrity checks for the downloaded shellcode
- Add new download methods, crypters
- Add web/dns server functionalities to auto-upload the shellcode files
