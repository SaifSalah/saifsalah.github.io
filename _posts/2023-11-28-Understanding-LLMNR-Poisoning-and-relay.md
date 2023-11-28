---
title: Understanding LLMNR Poisoning and relay
author: S41F
date: 2023-11-28
categories: [RedTeam, AD Recon, Pentesting]
tags: [Responder, SMB, LLMNR, T1171 Tactic, Credential Access]
---


## Introduction

Hey there! Today will talk about AD Recon and how we can get credential access while we are trying to get initial access by (LLMNR poisoning), By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials, so let's see how we can do that

## What's LLMNR Anyway?

Okay, so there's this protocol called LLMNR. It's part of Windows, and it's like a backup plan when our computers are trying to figure out the names of other computers on the same network. Imagine it as a kind of assistant to help out when the usual way of finding computer names (something called DNS) isn't working. There's also an older assistant called NBT-NS, but we won't get too deep into that right now.

Now, here's the interesting part. When LLMNR is doing its thing and someone asks for a file or something, it uses these things called NetNTLMv2 hashes to respond. It's like an NTLM Hash to make sure everything is secure. But, here's the catch, someone sneaky could take advantage of this process, as we discussed above adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials, so let's see how we can do that


### Setting Up Responder 

Before we start, we need to pick the network we want to check. It's a bit like choosing which road to watch. To do this, we use a simple command:

bash

`if config`

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/pic1.png?raw=true)
Now that we know which road we're watching, we can start Responder like this:

`responder -I eth0`

![](https://saifsalah.github.io/posts/Understanding-LLMNR-Poisoning-and-relay/?raw=true)

In simple terms, this command makes the Responder pay attention to certain questions and helps it figure out which devices are asking those questions.

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/pic2.png)

### Catching a User's NTLM Hashes :P

Once Responder is up and running, we just sit back and wait. Imagine someone trying to open a folder but making a little mistake in the name. Before they realize it, we've caught their hash (the NetNTLMv2 hash).

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/accessShare.png?raw=true)

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/picbefore3.png?raw=true)

Well well, the person might see a message saying the folder isn't accessible, but the trick has worked. On our end, Responder has grabbed the request and saved some details like the person's name, computer address, and NTLM Hash.

![](https://github.com/SaifSalah/saifsalah.github.io/blob/master/assets/img/pic3.png?raw=true)

And there you have it – LLMNR poisoning and we get the NTLM hash of the user then we can use John the Ripper or hashcat to crack the password.



