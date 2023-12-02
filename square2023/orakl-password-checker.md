# orakl password checker
We are given the following [program](./orakl-password-checker), which runs on remote, and we want to determine what the flag is. We can enter a flag, and the program will compare the flag to the true flag and tell us if we are right or not.

To examine the program, we will load it into Ghidra and examine `main`. All the 3 functions which we eventually decompiled are listed [here](./decompilation.md). Main takes in one argument (`argc`), reads in the password from stdin into an input buffer, and calls `secret_proprietary_super_advanced_password_checker` with `argc` and the input buffer. This function reads in the flag from `flag.txt`, then loops through every character in the input buffer. This loop terminates once we have checked every character in the input or the output of the `super_proprietary_super_advanced_password_checker_hasher` method is not 0. During the loop, we call the previously mentioned function with parameters of the current character in our input, the current character in the flag, and `argc` (from main). 

This computes the (absolute) character difference from the characters passed into the function, and then executes a syscall. It then returns that character difference. However, which syscall is called? One hint is that if we run the binary locally, and enter a false flag, the script takes very long to tell us that we've entered the wrong answer (and the challenge description mentions that it takes a long time as well): maybe it is a time-related syscall?

If we examine the disassembly of `super_proprietary_super_advanced_password_checker_hasher`, we see that `rsi` is set to 0, `rdi` is set to `[rbp-0x20]`, and `rax` is set to `0x23*[rbp-0x3c]` right before the syscall:
```asm
    ...
    1262:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    1266:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
    1269:	6b c0 23             	imul   eax,eax,0x23
    126c:	48 8d 7d e0          	lea    rdi,[rbp-0x20]
    1270:	be 00 00 00 00       	mov    esi,0x0
    1275:	0f 05                	syscall 
    ...
   ```
Our first hint is that the syscall, which is based on the value stored in `rax`, is a multiple of 0x23 = 35. Looking at a Linux syscall table, the most relevant syscalls for us to use could be 0\*35 = 0 (`sys_read`), or 1\*35 = 35 (`sys_nanosleep`). Since I noticed the sleeping behavior in the program before and the hints about time in the challenge flavortext, I assumed that the intended syscall was `sys_nanosleep`. But was there a way to control this syscall, as it seems that we may be able to control `rax = 0x23*[rbp-0x3c]` (perhaps to call `sys_read` or another syscall instead)?

I loaded the binary into GDB and ran it with a few parameters, then broke on the syscall. Running the binary normally, the value in `rax` was 0x23. I also ran the binary a few times with different values of `argc` (since this was passed into `super_proprietary_super_advanced_password_checker_hasher`, it could be relevant). I then discovered that the value of `argc` was stored in `[rbp-0x3c]`. Calling the binary normally would have `argc = 1`, which leads to the `sys_nanosleep` syscall. Also, the binary running on remote almost definitely has `argc = 1` as well: this could be verified by just running the program on remote a few times and observing its sleeping behavior. Since I couldn't modify `argc` over remote, I couldn't modify the syscall. Therefore, it seemed that I had to rely on a timing attack (over remote) to determine the flag. 

According to the man page for `sys_nanosleep`, there are two parameters: `const struct timespec *_req` and `struct timespec *_Nullable rem`, passed in from `rdi` and `rsi`, respectively. We know that `rsi` is set to 0, and according to the documentation, `rem` is allowed to be null; the sleep will still occur. The `timespec` struct specifies two numeric times `tv_sec` and `tv_nsec`, representing the time in seconds and nanoseconds to sleep, respectively. Since we are timing over remote, we just want to control seconds, so we just want to control the value stored in `[rdi]`.

Remember the "character difference" that we found in Ghidra? It was returned from `super_proprietary_super_advanced_password_checker_hasher`, but it didn't seem to be used outside of it. If we try our a few inputs, we can quickly see that `[rdi]` at the time of the syscall is indeed the character difference! Therefore, we can control the sleep based on the character difference with the flag: the character difference is the exact number of seconds that the program sleeps on a particular character comparison. This naturally leads to a timing oracle attack.

Recall that if two characters match in our input and the flag, `super_proprietary_super_advanced_password_checker_hasher` is then called on the next character (if the character difference is 0, then the loop condition in `secret_proprietary_super_advanced_password_checker` is satisfied). However, if our character difference is small but nonzero, then we know that our character "almost" matches the character at that position in the flag (and then the program will immediately terminate because the return value of `super_proprietary_super_advanced_password_checker_hasher` would not be 0). 

With this in mind, my strategy was to narrow down the "range" of characters for a particular character in the flag into one of five ranges. These ranges would be evenly spaced (with a length of 19) among all printable ascii characters. We pick a characteristic character from these ranges: `[v,c,P,=,*]`. This order of characteristic characters was chosen based on the frequency of types of characters in the flag: we expect to see a lot of lowercase, less uppercase, and even less special characters/numbers, so we prioritize them in that order to reduce wait times. We then append this character to the end of a known prefix of the flag. If the program terminates within 19/2 ≈ 10 seconds, then we know that the corresponding flag character is in the same range as the characteristic character. To add some leeway for the remote connection, I increased 10 seconds to 11 seconds. We can implement this using a timeout in pwntools: `r.recvline(timeout=11)`

Once we know a range a character is in, we test every character in the range until the delay becomes very large (if the character is correct, the program moves onto comparing the next characters in our input and the flag, in which case our input will have a newline character; this will almost definitely be very "far" from the character in the flag). In order to check for this, I set a timeout slightly larger than 19: 22. If the script terminates in less than 22 seconds, then our character is in the same range as the flag character but it is not correct. If the script terminates in more than 22 seconds, then we have the correct character, as the program is now comparing a newline to the next flag character. If we have found the right character, append it to the end of our prefix and repeat the previous range-finding process. We terminate the whole solve script once we find the true flag, which the program will notify us about.

There is a caveat though: if one of the characteristic characters we test is, in fact, the actual character of the flag in that position, then the delay of the program will be very large even though the flag character is in that range. In this case, we have to append that character manually to our prefix. Usually, this character is very determinable from context (the only options are the five characteristic characters), and in this challenge we only had to do it once: to guess the v in `wouldve`. In my final solve script below, I will include `wouldve` in the initial prefix, but my initial prefix could be empty. 

# Flag
`flag{i_wouldve_used_argon2_but_i_didnt_want_to_kill_our_infra}`

# Solve Script
```python
#!/usr/bin/env python3

from pwn import *
import string
import time
characteristic = "*=Pcv"[::-1]
char_range = [(32,51),(51,70),(70,89),(89,108),(108,127)]
char_range.reverse()
FLAG = "flag{i_wouldve"
FLAG_LEN = 0x40 - 1 #nullbyte

exe = ELF("./orakl-password-checker_patched",4)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path, '\4'])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("184.72.87.9", 8006)

    return r



def main():
    global FLAG, FLAG_LEN, characteristic, char_range


    print(FLAG)
    for i in range(FLAG_LEN-len(FLAG)):
        range_true = (0,0)
        # NOTE: it is possible that the characters you loop through here are actually part of the flag, in which case all of the characteristics will timeout -- you will need to pick that character manually in this case. This happened once with a v, but the v made complete sense in context.
        for i,c in enumerate(characteristic):
            print(FLAG+c)
            r = conn()
            r.recvline()
            r.sendline((FLAG+c).encode())
            try:
                data = r.recvline(timeout=11)
                print(data)
                if (len(data) == 0):
                    r.close()
                elif (data[:3] == b"Hey"):
                    print(FLAG+c)
                    return 0
                else:
                    r.close()
                    range_true = char_range[i]
                    print(f'proceeding with {c}')
                    break
            except Exception as e:
                r.close()
        for i in range(range_true[0],range_true[1]):
            c = chr(i)
            r = conn()
            r.recvline()
            r.sendline((FLAG+c).encode())
            try:
                data = r.recvline(timeout=22)
                if (len(data) == 0):
                    FLAG = FLAG+c
                    print(FLAG)
                    r.close()
                    break
                elif (data[:3] == b"Hey"):
                    print(FLAG+c)
                    r.close()
                    return 0
                else:
                    r.close()
            except Exception as e:
                r.close()

if __name__ == "__main__":
    main()
```
 



