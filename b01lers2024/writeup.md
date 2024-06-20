# Propagating Counter Block Chaining
## b01lers CTF 2024, Crypto
### Description
Another counter mode challenge
### Observations
In this challenge, we are given a "certificate". Then, we can submit any new certificate. If this new certificate decrypts successfully and contains the flag, we are notified. Otherwise, we are notified if the decryption was successful or not. 

Next, we need to determine how certificates are created and encrypted. From just examining the encrypt method, we can understand this. First, we create a random IV that is one block large. Then we create two "counters" based on two random 8-byte nonces. Now, we "pad" the message to fit a block boundary. Then, for each block, we do the following.
- AES-ECB encrypt the first counter. Set enc1 to this value
- AES-ECB encrypt (block xor previous block xor enc1). Set enc2 to this value.
- AES-ECB encrypt the second counter. Set enc3 to this value.
- The current encrypted block will then be enc2 xor enc3

This encryption scheme is very similar to AES-PCBC (link). Decryption is very similar, just done in reverse. When we encrypt a message, we get the IV+encrypted blocks back.

Since we get infinite tries to decrypt a certificate, I first thought to just mess with the given (valid) certificate and see what happens. To my surprise, I got a bunch of "Something went wrong" messages, which indicate that an Exception was triggered in the code. This is weird, because normally you wouldn't code something that errors that easily. As we will see later, this error message turns out to be a very useful side-channel to solving this challenge. 

Even more weirdly, I noticed that modifying characters at the start of the certificate resulted in a successful decryption (but not a correct one) -- the message displayed was instead "This certificate is not valid". To investigate this, I modified the given source code to print an exception if it occurs and also to print the decrypted certificate if this is possible to recover. Then, in the first case where I got error messages, I saw the error was "Padding was incorrect." In the second case, if I modified one character in the first 16 bytes of the certificate, then exactly one character per block was modified in the decrypted certificate compared to the original one. Specifically, if one bit is flipped in the first 16 bytes, the bit in the same position of each block is flipped. 

This is interesting, because it hints that each block is XORed with these first 16 bytes. Upon looking at the source code, I also noticed that these first 16 bytes are the IV (or nonce, I will use these terms interchangeably in this writeup), compared to everything else in the certificate which was actual AES output. With more testing, I noticed that the padding error would occur on editing any byte in the AES output, but it would not happen on editing a byte in the IV.

At the same time, I noticed that the end of the decrypted certificate had a lot of `\r`  (0x13) bytes. I knew this was some kind of padding scheme, and with the previous error relating to incorrect padding, maybe there is something going on here. So, I edited the last byte in the IV, asked the oracle to decrypt the cipher, and saw that the decryption had the last padding byte modified, but also received an error about incorrect padding. This was important, because it meant that different modifications to the IV resulted in different messages: either "This certificate is valid" or "Something went wrong".

I looked into the padding scheme a bit more. The scheme was [PKCS](https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method), which pads the message with bytes until it reaches a block length. If it adds n bytes to the message, each byte it adds has a hex value of n. Therefore, if 13 bytes are needed to pad the message to a block length, each byte added is 0x13 (`\r`). 

### Padding oracle
I then realized that it is possible to use these "error" messages as an oracle to determine each byte of the plaintext starting from the end.

Consider a plaintext + padding of the following form:
`bytes ... unknown_byte \x01`
 Where `0x01` is the one padding byte that conforms to PKCS padding. 
If the IV is 16 bytes long, consider if we modify the IV as following
 `IV' = IV[0:14] + [IV[14] ^ test_byte ^ \x02] + [IV[15] ^ \x01 ^ \x02]`
 We will call the first 14 bytes of the modified IV here the "**invariant part**", the next byte the "**IV guess byte**", and the last byte(s) the "**known IV padding**" in the rest of the writeup. 
 
 Then, our decrypted plaintext, as per our previous observations, would look like so:
 `bytes ..., (unknown_byte ^ test_byte ^ \x02), \x01 ^ \x01 ^ \x02`
 There are two cases
 - `bytes ..., \x02, \x02` if `unknown_byte` = `test_byte`
 - `bytes ..., (unknown_byte ^ test_byte ^ \x02), \x02` if `unknown_byte` != `test_byte`.

The first case will pass the padding check, but the second will error since it doesn't repeat the byte `\x02` twice.  Therefore, we can select a bunch of `test_byte`s and observe the output to determine if our `test_byte` is the actual byte of the plaintext. We know we have selected the right one when the output is "Certificate is not valid" instead of "Padding is incorrect". 

In this challenge, the flag is padded in the beginning and end with 8 random bytes. Therefore, to fully recover the flag, we have to make `256*(flag_len + 8)` guesses (256 per byte), which isn't too many. However, there is the issue that we don't actually know what the padding bytes are when solving the challenge, as we can't just print out our plaintext certificate. 


### Solve
To solve the aforementioned issue, we'll assume that there aren't any padding bytes already and we will try to coerce the last byte of the plaintext to be `\x01`: 1 valid padding byte, no matter what the actual padding bytes in the plaintext are. In practice, this could mean that our plaintext looks something like `...\r\r\r\r\r\r\r\r\r\r\r\r\x01` after the coercion, but this is still valid PKCS padding. 

Overall, our strategy will take the following steps
- Receive a certificate from the oracle, with an IV + encrypted message
- Initialize the number of desired padding bytes `num_pad` to 1
- Initialize a string `recovered_flag` to store our recovered characters
- Loop indefinitely (or keep a counter and exit when the counter passes a certain number of bytes)
	- If `num_pad` reaches 0, set it to 16 (as in PKCS, you cannot have 0 padding bytes; you must have a whole padding block of 16 bytes if no padding bytes can be added to the previous block)
	- If `num_pad` reaches 1 (not on the initial iteration), increment a `blocks_removed` counter
	- Loop over 256 possible bytes for the `test_byte` (we are guessing from the end of the flag + padding)
		- Skip the iteration if `num_pad` is 1 as well as `test_byte`. This causes issues on the very first byte you guess, because it automatically determines that `\x01` is the correct last byte of the plaintext. When this is used to create the test IV, we observe that this creates the same IV, which actually produces the same plaintext as the original. This means that our oracle will report "The certificate is not valid", which will trigger a false positive since we didn't actually change the plaintext.  
		- Also set the bytes `test_pads` to the padding bytes you want to coerce in the plaintext based on the ones you already have done so. This means that if you already have coerced the padding bytes `\x02 \x02` to be padding bytes in the previous iteration, you want those to be `\x03 \x03` now (we are using the third padding byte required here to guess the next byte of the plaintext). This is done by simply creating the byte array `bytes([num_pad] * (num_pad-1))`
		- Create the invariant part of the IV. This is the first `16-num_pad` bytes of the nonce: `nonce[0:(16-num_pad)]`
		- Create the IV guess byte: `nonce[16-num_pad] ^ test_byte ^ num_pad`
		- Create the known IV padding with the rest of the nonce: `nonce[16-num_pad+1:] ^ recovered_flag[:num_pad-1]^ test_pads`. We aren't using the entire recovered plaintext here because we need to reset once we recover one "block" of the plaintext, so instead we are just using the most recent `num_pad-1` bytes of the plaintext we have found.
		- Now construct the IV that we will send: `new_nonce = invariant_nonce + guess + determined`
		- Append the encrypted message to the nonce. Remove whole blocks from the end of it based on `blocks_removed`. This allows us to guess multi-byte flags, as we can reset our padding oracle on a different block of the ciphertext.
		- Send the certificate to the oracle. If it is invalid, instead of the oracle reporting that something went wrong, we have found the correct `test_byte`! Prepend this to the `recovered_flag`.

The solve script can be found here.

### Infrastructure

b01lers really liked long flags, so I had to let this brute force run on remote for a long time. Naturally, this meant their infrastructure gave out in the middle of solving the challenge and I only had part of the flag: `_security_to_padding_oracle..._c850d60d210169}`. This was kind of bad, because I was out eating lunch and the CTF was going to end in a few hours.  Also, using the saved progress is awkward because of the 8 random bytes appended to the end of the plaintext, meaning reusing this plaintext isn't easy. Thankfully Ronak @ronak came to the rescue! The solution was to let the script run to guess the 8 random bytes at the end, and as soon as it saw the `}` byte, we would automatically set `test_byte` to its known correct value until we run out of known bytes. This modified script can be found here.

## Flag
`bctf{adding_ctr_mode_doesn't_provide_any_security_to_padding_oracle..._c850d60d210169}`

