# Encrypted_Bind_Shell

Bind Shells

Bind shells have the listener running on the target and the attacker connect to the listener in order to gain a remote shell.
There is a security issue with bind shells, though, and that is the fact that anyone can connect to the bind shell and run commands. A malicious actor can take advantage of this easily.
There is another key issue with bind shells, and that is the fact that if we were trying to connect to an internal host’s bind shell, 2 things could prevent us:
1. Firewalls often have strict inbound traffic filtering
2. NAT/PAT translation process changes the private IP address (RFC 1918) into different public IP addresses, and can even change the port
We can try and resolve issue 1 by setting the target’s bind shell to listen on a popular port, such as 443, but it is possible that the firewall blocks external connections from even the most popular ports. Is there a better way to gain a remote shell from a target, without having to face the security, firewall and NAT/PAT issues?

Reverse Shells

The answer is — yes!
Reverse shells have the listener running on the attacker and the target connects to the attacker with a shell.
Reverse shells solve a lot of headache that bind shells caused us, let’s see how it has solved each of the 3 issues.
1. Reverse shells remove the need for a listener on the target machine, which means we don’t have to leave the target vulnerable to other malicious actors.
2. Reverse shells can use popular ports (e.g. 80, 443) which are usually allowed on egress connections from an internal network to an external network, bypassing firewall restrictions.
3. We do not need to specify the remote host’s IP address, and therefore do not have to face NAT/PAT address translation.
Both bind and reverse shells can be gained through common tools such as Netcat, and as a payload alongside an exploit in exploit frameworks like Metasploit.

Encrypted Shells

Both bind and reverse shells communicate in plaintext. That means anyone can sniff the network and easily see the bidirectional communications. And what’s worse, security analysts can look at what commands you executed on the target, what files you exfiltrated or uploaded to the target, as well as figure out what you were trying to do.
Let’s take a look at this plaintext communication in Wireshark.
This is a very basic example, but it clearly demonstrates the insecure nature of plaintext shells. We have captured 20 packets, and following the TCP stream shows us both the commands that we executed and the output the target returned. In this case, it seems like the attacker (in red) has gained root privileges on the target (in blue), has found a .txt file containing several passwords and is attempting to exfiltrate this file by setting up a HTTP server that listens on port 443 (quick note: HTTP is another plaintext protocol).
This is exactly where encrypted shells kick in. Encrypted shells, as the name suggests, encrypt the communication, thereby disallowing intermediary sniffers to decipher what we are trying to accomplish on the target machine.


For clear understanding of the program use vscoode with Better commmands extension installed
