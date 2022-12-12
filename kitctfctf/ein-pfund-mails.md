# ein-pfund-mails
Someone leaked a bunch of emails from the CTF orga. Sadly there is no way to know which one is real...
## Solution
We are given a zip file with many `.eml` files. Let's take a look at one of them.
```eml
... (email header)
--000000000000a433c905e191f775
Content-Type: text/plain; charset="UTF-8"

Hi,

die Flag ist KCTF{c5a868bc2cd7c803acf19b28b314dd5b}

LG
Martin

--000000000000a433c905e191f775
Content-Type: text/html; charset="UTF-8"

<div dir="ltr">Hi,<div><br></div><div>die Flag ist KCTF{c5a868bc2cd7c803acf19b28b314dd5b}</div><div><br></div><div>LG</div><div>Martin</div></div>

--000000000000a433c905e191f775--
```
This has a flag in it, but it's probably wrong -- after all, the challenge description mentions that only one is "real". There is also an email header with a lot of information. Could this be useful? <br>
Running `diff` on two eml files tells us that the only difference between them is the flag itself: 
```zsh
10c110
< die Flag ist KCTF{c5a868bc2cd7c803acf19b28b314dd5b}
---
> die Flag ist KCTF{6f4eeaa9cd5dbfd5b253c96982c195bb}
118c118
< <div dir="ltr">Hi,<div><br></div><div>die Flag ist KCTF{c5a868bc2cd7c803acf19b28b314dd5b}</div><div><br></div><div>LG</div><div>Martin</div></div>
---
> <div dir="ltr">Hi,<div><br></div><div>die Flag ist KCTF{6f4eeaa9cd5dbfd5b253c96982c195bb}</div><div><br></div><div>LG</div><div>Martin</div></div>
```
We can run diff a few more times to confirm this. So, which one of these flags is right if all the email headers are the same? I did some research on eml file headers and wondered if the hash of the email message is stored in these headers. After all, hashing the message is required for creating signatures and related things that could be found in an email header. And sure enough, the email body hash is stored in the eml file. <br>
To confirm this, I used [this website](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx) to analyze an email header. The website tells me the following, meaning that the body hash is stored in the email header. ![image](https://user-images.githubusercontent.com/42781218/206948667-6047951f-3b5c-4d69-801d-4c3e5420079d.png)
Specifically, the body hash is stored in the DKIM signature of the email in the `bh=` field: ![image](https://user-images.githubusercontent.com/42781218/206948762-20a06668-b129-4bfd-ad77-a079f0347b78.png)
Since every email header is the same, I deduced that we are looking for an email whose content produces a hash of `Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk=`. But how is this hash generated? <br>
The hash looks base64-encoded. Also, in the DKIM signature of the email header, you can see `a=rsa-sha256`. I thought this meant that the SHA256 hash of the message is calculated, stored as bytes, encoded with base64, and then stored in bh. After doing some more research, I confirmed this to be true. <br>
Time to begin scripting. I found [this writeup](https://ediscoverychannel.com/2021/02/28/nothings-dkimpossible-manually-verifying-dkim-a-ctf-solution-and-implications/), helping me confirm all of my thoughts and find which part of the email message was used for the hash (all of it). So, I wrote a Python script to calculate the hash of every email and compare it to the target hash. Note: the email content was found between lines 104-119, inclusive and 0-indexed. Also, I noticed that the line endings of the eml file in this writeup were CRLF instead of the usual LF. I didn't pay attention to it at first and assumed that it was just due to a different eml file being used. I was wrong.
```py
from os import listdir
from os.path import isfile, join
import hashlib
import base64
mypath = '.'
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f)) and 'eml' in f] # https://stackoverflow.com/questions/3207219/how-do-i-list-all-files-of-a-directory
hashes = []
body = ""

for i in onlyfiles:
	with open(i,'r') as f:
		lines = f.readlines()
		body = ''.join(lines[104:120])
		h = hashlib.new('sha256')
		h.update(body.encode('utf-8'))
		d = h.digest()
		bh = base64.b64encode(d)
		hashes.append(bh.decode())
		
target = 'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk='
if (target in hashes):
	print("success")
	print(onlyfiles[hashes.index(target)])
```
When I ran this, no success. Back to the drawing board. The writeup mentioned canonicalization, and I assumed that I parsed the email incorrectly. I found [this script](https://github.com/kmille/dkim-verify/blob/master/verify-dkim.py) which handles canonicalization and can calculate a body hash. I modified it for my purposes. Surely, this works? <br>
Unfortunately, this script only handles simple email messages, and our email was in MIME Multipart format, meaning that the statement `mail.get_payload()` returns a list instead of a string. This prevented the script from running successfully. <br>
So, I tried to actually figure out what canonicalization is. Eventually, I found [this writeup](https://ctftime.org/writeup/33281) and found this line of code: `canonicalized_body = body.strip().encode().replace(b"\n",b"\r\n") + b"\r\n"`. <br>
Oh. The CRLF endings from the first writeup were actually important, as this writeup makes sure to replace `"\n"` (LF) with `"\r\n"` (CRLF). With this in mind, I modified my original script to do this replacement as well: `h.update(body.encode('utf-8').replace(b"\n",b"\r\n"))`. <br>
Also, I made sure that my string ends with a `\n` before replacement as well: `print(ord(body[-1]))` <br>
Running my script, we have a success: `438b5.eml`! <br>
The flag from `438b5.eml` is `KCTF{1f8e659e892f2b2a05a54b8448ccbff9}`. Just to sanity check, entering this eml file [here](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx) tells us that the body hash is verified!

## Flag: KCTF{1f8e659e892f2b2a05a54b8448ccbff9}
## Solve script
```py
from os import listdir
from os.path import isfile, join
import hashlib
import base64
mypath = '.'
onlyfiles = [f for f in listdir(mypath) if isfile(join(mypath, f)) and 'eml' in f] # https://stackoverflow.com/questions/3207219/how-do-i-list-all-files-of-a-directory
hashes = []
body = ""

for i in onlyfiles:
	with open(i,'r') as f:
		lines = f.readlines()
		body = ''.join(lines[104:120])
		#print(ord(body[-1]))
		h = hashlib.new('sha256')
		h.update(body.encode('utf-8').replace(b"\n",b"\r\n"))
		d = h.digest()
		bh = base64.b64encode(d)
		hashes.append(bh.decode())
		
target = 'Hc1fzmKy9aocJCtYl88l4HEWgiYgp/nBHaexg4xOWtk='
if (target in hashes):
	print("success")
	print(onlyfiles[hashes.index(target)])
```
