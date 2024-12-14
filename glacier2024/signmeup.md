# signmeup

GlacierCTF 2024 - Crypto

Forging an insecure Ed25519 signature

Writeup by [Arnav Vora](https://github.com/AVDestroyer) for [PBR | UCLA](https://pbr.acmcyber.com/).

> We improved the Speed of EdDSA; certainly it's way more secure than before.

Note: I didn't get to solve this challenge during the CTF, but I upsolved it afterwards with the help of [this writeup](https://github.com/plvie/writeup/blob/main/glacierctf2024/signmeup/writeup.md). I still really enjoyed doing this challenge and I learned a lot about lattices and insecure signature schemes along the way. The last time I checked, I think this challenge had less than 10 solves (but maybe it got more later).

## Challenge

We are given some *Rust* code that implements an [EdDSA](https://en.wikipedia.org/wiki/EdDSA) signature scheme, specifically Ed25519 (Curve 25519). We have a remote that we can interact with:

```rust
fn main() -> Result<(), Box<dyn Error>> {
    let flag = fs::read_to_string("flag.txt")?;
    let flag = flag.trim();

    let mut csprng = OsRng;

    let key_bytes: [u8; 32] = csprng.gen();
    let private_key = PrivateKey::new(key_bytes);

    println!("public key: {}", hex::encode(private_key.public_key.as_bytes()));

    loop {
        print!("msg> ");
        io::stdout().lock().flush()?;

        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let line = line.trim();

        if line.is_empty() {
            break;
        }

        let (r, s) = private_key.sign(line.as_bytes());

        println!("signature: {} {}", hex::encode(r.as_bytes()), hex::encode(s.as_bytes()));
    }

    let challenge = generate_challenge(32);
    println!("sign this: {}", challenge);
    print!("signature> ");
    io::stdout().lock().flush()?;

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;

    let (r_hex, s_hex) = line.trim().split_once(' ').ok_or("bad input")?;

    let r_bytes = hex::decode(r_hex)?;
    let s_bytes = hex::decode(s_hex)?;

    let r = CompressedEdwardsY::from_slice(&r_bytes)?;
    let s: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes.try_into().map_err(|_| "invalid scalar length")?).into();
    let s = s.ok_or("scalar out of range")?;

    match private_key.public_key.verify(challenge.as_bytes(), (r, s)) {
        Ok(_) => println!("{}", flag),
        Err(_) => println!("Better luck next time"),
    }

    Ok(())
}

```

We first receive a public key. Then, we can send messages to sign and we receive the signatures. We can do this as many times as we want. Once we are done, we can send an empty line. Then, the server sends us a randomly generated challenge message and we have to forge its signature, without the private key. If we can do this, we get the flag. The randomness used to generate the challenge message is secure.

To break the signature scheme, we would have to perform a [universal forgery](https://en.wikipedia.org/wiki/Digital_signature_forgery#Universal_forgery_(universal_unforgeability,_UUF)) with a challenger-generated message. This is one of the most difficult methods to forge a signature. And Ed25519 is known to be secure against all forgery methods. So how will we solve this challenge?

We are also provided with a custom implementation of the Ed25519 signature scheme:

```rust
use std::error::Error;

use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use ed25519_dalek::{hazmat::ExpandedSecretKey, SigningKey};
use digest::Digest;

use sha1::Sha1;

type HashType = Sha1;
const HASH_LEN: usize = 20;

pub struct PrivateKey {
    hash_prefix: [u8; 32],
    secret_scalar: Scalar,
    pub public_key: PublicKey,
}

pub struct PublicKey{
    compressed: CompressedEdwardsY,
    point: EdwardsPoint,
}

impl PrivateKey {
    pub fn new(secret_seed: [u8; 32]) -> Self {
        let key_pair: SigningKey = SigningKey::from_bytes(&secret_seed);
        let expanded_key: ExpandedSecretKey = (&secret_seed).into();
        let public_key = PublicKey::from_bytes(key_pair.verifying_key().as_bytes()).unwrap();
        Self {
            hash_prefix: expanded_key.hash_prefix,
            secret_scalar: expanded_key.scalar,
            public_key,
        }
    }

    pub fn sign(
        &self,
        message: &[u8],
    ) -> (CompressedEdwardsY, Scalar)
    {
        let mut h = HashType::new();
        h.update(&self.hash_prefix);
        h.update(message);

        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice());

        let r_scalar = Scalar::from_bytes_mod_order_wide(&hash_val);
        let r: CompressedEdwardsY = EdwardsPoint::mul_base(&r_scalar).compress();

        let mut h = HashType::new();
        h.update(r.as_bytes());
        h.update(self.public_key.compressed.as_bytes());
        h.update(message);

        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice());

        let h_scalar = Scalar::from_bytes_mod_order_wide(&hash_val);
        let s: Scalar = (h_scalar * self.secret_scalar) + r_scalar;

        (r, s)
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let compressed = CompressedEdwardsY::from_slice(bytes)?;
        let point = compressed.decompress().ok_or("decompression failed")?;
        Ok(Self{compressed, point})
    }

    pub fn verify(&self, msg: &[u8], signature: (CompressedEdwardsY, Scalar)) -> Result<(), ()>
    {
        let (r, s) = signature;
        let mut h = HashType::new();
        h.update(r.as_bytes());
        h.update(self.compressed.as_bytes());
        h.update(msg);

        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice());

        let c = Scalar::from_bytes_mod_order_wide(&hash_val);
        let minus_a = -self.point;

        let expected_r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &minus_a, &s);
        let expected_r = expected_r.compress();

        match r == expected_r {
            true => Ok(()),
            false => Err(()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        return self.compressed.as_bytes();
    }
}

```

Most of this code uses the `curve25519_dalek` and `ed25519_dalek` crates, which implement standard Ed25519 signatures using Curve 25519, which is an industry-standard secure curve. Specifically, we use standard implementations of elliptic/edwards curve operations as well as hash prefixes of our private key. 

### EdDSA

How exactly does the EdDSA signature scheme work, though? Just like any signature scheme, there are three functions: `keygen`, `sign`, and `verify`. Before any of these are run, we first agree on a few things:

- The curve and a finite field (in this case, Curve 25519)
    - The base point $B$ we use is x = 9
    - The order of the generated subgroup from the base point is $l$, a known large 252-bit prime
    - All points in the curve can be represented with $b$ bits in *compressed format*. We can choose compressed-X or compressed-Y coordinates. In this challenge, we used compressed-Y format. Ed25519 uses *Twisted Edwards Curves*, which are slightly different from elliptic curves but isomorphic to them. Here, the $b-1$ least significant bits are used to store the y-coordinate, and the most significant bit is a sign bit for the x-coordinate. Compressed points are stored little endian. For Ed25519, $b = 256$.
- A cryptographic hash function $H$ with 2b-bit outputs. For Ed25519, we should use SHA512. We use this for some scalar values, all of which the hash function outputs in little endian.

For `keygen`:
- Choose a private key $k$, a uniform randomly chosen b-bit string.
- Compute a scalar $s = H_{0,\cdots,b-1}(k)$, or the first (least significant) $b$ bits of $H(k)$.
- The public key is $A = sB$. Distribute this in compressed format ($b$ bits).

For `sign`:
- A signature is the tuple $(R, S)$, where $R$ is a curve point ($b$ bits) and $S$ is a $b$-bit little endian scalar. The signature is therefore $2b$ bits overall.
- Let $r$ = $H(H(k) || M)$, where $||$ denotes concatenation. Then $R = rB$.
- For a message $M$, $S \equiv r + H(R || A || M)s \mod{l}$.

For `verify`:
- Check if the following holds for a signature $(R,S)$ and message $M$: $SB = R + H(R||A||M)A$.

### What is the challenge doing?

Is the challenge implementing standard Ed25519? There is one glaring difference: **it uses two different hash functions: $H_1$ and $H_2$**! $H_1$ is SHA512, as usual, and it is used to hash the private key. However, $H_2$ is SHA-1! It is used in two places: to compute the final value of $r$, and in the computation of $S$ as the scalar multiple of $s$. This doesn't make a lot of sense: SHA-1 produces 160-bit outputs but we really want 512-bit outputs from SHA512. Notably, the 160-bit outputs are smaller than the modulus $l$, which is 252 bits.

Everything else in the challenge is mathematically equivalent to standard Ed25519, so the vulnerability is probably in this hash function, right?

### Missing bits

Since we can ask for as many signatures we want for our own messages, we get a lot of values of $S$. After receiving $S_i$, notice that there are only two unknowns, $r$ and $s$: The values of $R_i$ (given in the signature), $A$ (public key), and $M_i$ (message) are all known. For message $M_i$, let $h_i = H_2(R_i || A || M_i)$. Then, we know that $S - r_i \equiv h_is \mod{l}$. Also note that while $r_i$ depends on $M_i$, $s$ does not. 

Why is this useful? Since $r_i$ is also computed using $H_2$ (SHA-1), it is only 160 bits, while $S_i$ is 252 bits. This gives us about 92 bits of information about the value of $h_is \mod{l}$. More specifically, if $b = 2^{160}$, we can say that $S_i - b \leq h_is \mod{l} \leq S_i$.

If we query a bunch of signatures, we are left with many of inequalities in the above format. We also know that $0 \leq s \leq 2^{256}$. This feels familiar to a [challenge I have written before](https://hackmd.io/@Arnav-Vora/rJ60YkPQkx)! If we have inequalities on linear functions of some variables in a finite field, we can rewrite such inequalities as a matrix equation and solve the system using lattices! I will gloss over the details about this method; if you want to learn more, read my writeup for `lactf/any-percent-ssg` (linked above). How does this help us? Potentially we can set up a system that allows us to recover the value of $s$, which will never change.

### Lattices

If we request $n$ signatures, we have $n+1$ unknowns ($s$ and $k_i$ for $i = 1, \cdots, n$) and $n+1$ equations (one per signature, plus the initial constraint on $s$). This lets us set up a square matrix for our lattice. If we receive signature $(R_i, S_i)$, let $h_i$ be the value $H_2(R_i || A || M_i) \mod{l}$ that we can compute. Define the following:

$$
\mathbf{A} = \begin{bmatrix}
1 & 0 & 0 &  \cdots & 0 \\ h_1 & l & 0 & \cdots & 0 \\ h_2 & 0 & l & \cdots & 0\\ \vdots & \vdots & \vdots & \ddots & \vdots \\ h_n & 0 & 0 & \cdots & l  
\end{bmatrix} , \hat{x} = \begin{bmatrix}
s \\ k_1 \\ k_2 \\ \vdots \\ k_n
\end{bmatrix}, 
\hat{min} = \begin{bmatrix}
0 \\ S_1 - b \\ S_2 - b \\ \vdots \\ S_n - b
\end{bmatrix} 
\hat{max} = \begin{bmatrix}
2^{256} \\ S_1 \\ S_2 \\ \vdots \\ S_n
\end{bmatrix}
$$

Then we know that $\hat{min} \leq \mathbf{A}\hat{x} \leq \hat{max}$. We just need to find some $\hat{x}$ that satisfies the equation, and its first element will be the value of $s$ we are looking for. We can represent the column vectors of $\mathbf{A}$ as a basis of some lattice in $\mathbb{R}^{n+1}$, where the inequality now defines a "box" in n+1 dimensions where a lattice point ($\hat{x}$) must lie. 

To make this point easier to find, we can use lattice reduction to find a short, almost orthogonal basis $\beta'$ of the lattice. This is done with an algorithm like LLL. Suppose the basis is stored in the columns of an LLL-reduced matrix $\mathbf{A}'$. We apply the inverse transformation for this basis (left-multiply by $\mathbf{A}'^{-1}$) to the lattice to get a new lattice which is simply $\mathbb{Z}^{n+1}$ (just integer points in n+1 dimensions). We also apply this inverse transformation to the "box" to get a n+1-dimensional *parallelotope* where a lattice point must lie now. All we have to do is find an integer point ($\hat{x}'$) inside this transformed parallelotope. 

Since LLL tries to find a short, almost orthogonal basis, the parallelotope we find should have wide angles and contain lattice points near its midpoint (in theory). So if we compute its midpoint, and search for integer points around that midpoint, we should be able to find an integer point located inside the parallelotope. To check if an integer point $\hat{x}_{test}'$ is inside the parallelotope, we can simply compute $\mathbf{A}'\hat{x}_{test}'$ and check if it satisfies the original inequality: $\hat{min} \leq \mathbf{A}'\hat{x}_{test}' \leq \hat{max}$.

Let's try to implement this attack to recover $s$. I will skip some of the pwntools reading/parsing inputs to focus on the math for now:

```python
l = 2 ^ 252 + 27742317777372353535851937790883648493

N = 10 # note that this is not n as described earlier (sorry), N = n + 1

pk = # we receive a public key

mins = [0]
maxs = [2**256]
col0 = [1]

for i in range(N-1):
    random_string = # generate a random string
    msg = random_string.encode()

    h = hashlib.sha1()
    
    # send the random message when prompted
    R, S = # receive R and S

    assert (S < l)

    # generate H(R || A || M)
    h.update(binascii.unhexlify(R.encode()))
    h.update(pk)
    h.update(msg)

    hi = h.digest()

    # S = r + hi * s

    mins.append(S - 2^160)
    maxs.append(S)
    col0.append(bytes_to_long_le(hi) % l)

# Create the min and max vectors
minvector = vector(ZZ, mins)
maxvector = vector(ZZ, maxs)    

# create the A matrix
a_helper = [[0] * N for j in range(N)]
for j in range(1,N):
    a_helper[j][j] = l
for j in range(N):
    a_helper[j][0] = col0[j]

A = matrix(ZZ, a_helper)

# Compute LLL (LLL in sage operates on rows so you need to do some 
# transposes)
# and compute inverse transform
AL = A.transpose().LLL().transpose()
ALi = AL.inverse()

LHSt = ALi*minvector
RHSt = ALi*maxvector  

# Find midpoint
midpoint = ((RHSt) + (LHSt)) / 2

solutions = []

# For each guess, log the number of coordinates it has guessed "correctly".
# If a guess is correct, it should guess N coordinates correctly.
num_corrects = {}

# Brute force around the midpoint to find integer points inside the
# parallelotope.
for j in range(2**N):
    consider = []
    for k in range(N):
        num = midpoint[k]
        if j&(1 << k): 
            num = floor(num)
        else:
            num = ceil(num)
        consider.append(num)

    # transform back to the original lattice (A' * x')
    considerVec = vector(ZZ,consider)
    check = AL*considerVec

    # check if the current point is inside the box
    correct = True
    num_correct = 0
    for k in range(N):
        if (minvector[k] > check[k] or maxvector[k] < check[k]):
            correct = False
        else:
            num_correct += 1
    if num_correct in num_corrects:
        num_corrects[num_correct] += 1
    else:
        num_corrects[num_correct]  = 1
    if correct:
        solutions.append(check)

# list solutions
for solution in solutions:
    print(f'Potential value of s: {solution[0]}')
print(num_corrects)
```

### it doesn't work :(

And... this found no solutions. None of the guesses even found more than 1 correct coordinate (i.e. they only satisfied the inequality $0 \leq s \leq 2^{256}$). What's wrong?

To diagnose the issue, I calculated the differences between each coordinate of the transformed min and max vectors. If these differences are too large, that is an indication that the parallelotope is not small, and more importantly, it does not have near-orthogonal angles. This would make it narrow and would make it much more difficult to find an integer point inside.

```
558177.5176385666
-1060960.0
-224784.0
-2772688.0
1142912.0
-407568.0
418624.0
-1977968.0
-954640.0
-990208.0
```

Yikes... that is way too high. Ideally, we want these differences to be in the single digits so that the search space of the entire parallelotope is small. But shouldn't LLL and lattice reduction have already fixed this issue?

### Get smaller

I wasn't really sure what to do at this point. Was this still the right path? I used [this writeup](https://github.com/plvie/writeup/blob/main/glacierctf2024/signmeup/writeup.md) to guide me a little, and I figured out some ideas about making my lattice solution better. Specifically, the min and max vectors should have small values that are all roughly of the same order, to ensure the "box" would be small and close to 0 in the lattice. Right now, each inequality on $h_is + k_il$ covers a range of 160 bits, but the two ends of the ineqalities ($S - b$ and $S$) are themselves 256 bits, which might be awkward. Also, it doesn't help that our first inequality is a 256-bit inequality instead of a 160-bit inequality like the rest of them.

What if, instead, our inequalities were on values of $r_i$ instead of $h_is + k_il$? We know that $r_i = S_i - h_is - k_il$ (another way of saying $r_i \equiv S_i - h_i s \mod{l}$). Since each $r_i$ is 160-bit, we know that $0 \leq S_i - h_is - k_il \leq 2^{160} = b$. Note that currently, this is simply rearranging the first inequalies we used. There is still a problem: $S_i$ are constant values, how can we add them to our matrix? 

Let's introduce a bias variable $y$ that is just 1. That means $r_i = S_iy - h_is - k_il$. Since this is a new variable, we need a new inequality/constraint on it too. Note that now, we want all our inequalities to be of the same order (160-bit) to make LLL choose a more orthogonal basis. The new inequality is a trivial one, but it is still necessary: $b \leq by \leq b$.

Finally, we need to rewrite the first inequality on $s$ to also be a 160-bit inequality: $0 \leq \frac{b}{2^{256}} s \leq b$.

Note that we haven't mathematically changed our system of inequalities at all; we only have rearranged them, applied some constant scaling, and introduced an extra trivial inequality. However, our new inequality system is much more compatible with lattice reduction since the inequalities are smaller and all of the same order. We now have n+2 inequalities for n+2 variables.

We now have $\hat{min} \leq \mathbf{A} \hat{x} \leq \hat{max}$ for:
$$
\mathbf{A} = \begin{bmatrix}
b/l & 0 & 0 &  \cdots & 0 & 0 \\ -h_1 & l & 0 & \cdots & 0 & S_1 \\ -h_2 & 0 & l & \cdots & 0 & S_2 \\ \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\ -h_n & 0 & 0 & \cdots & l & S_n \\ 0 & 0 & 0 & \cdots & 0 & b
\end{bmatrix} , \hat{x} = \begin{bmatrix}
s \\ k_1 \\ k_2 \\ \vdots \\ k_n \\ y
\end{bmatrix}, 
\hat{min} = \begin{bmatrix}
0 \\ 0 \\ 0 \\ \vdots \\ 0 \\ b
\end{bmatrix} 
\hat{max} = \begin{bmatrix}
b \\ b \\ b \\ \vdots \\ b \\ b
\end{bmatrix}
$$

small note: since the value $S_i$ is computed modulo $l$, the value of $s$ can actually be bounded between $0$ and $l$ instead of $0$ and $2^{256}$. I will use this as the constraint in the above system. Also, since $k_i$ are arbitrary integers, it doesn't matter whether you add or subtract them in the inequalities.

### recovering s

Again, s is going to be the first element of $\hat{x}$. Note that our code finds a solution $\mathbf{A}'\hat{x}$, whose first element is $\frac{b}{l}s$, so we need to multiply this by $\frac{l}{b}$. Let's use the following code to recover $s$:

```python
l = 2 ^ 252 + 27742317777372353535851937790883648493

N = 10 # note that this is not n as described earlier (sorry), N = n + 1

pk = # we receive a public key

mins = [0]
maxs = [B]
col0 = [B / l]
coln = [0]

for i in range(N-1):
    random_string = # generate a random string
    msg = random_string.encode()

    h = hashlib.sha1()
    
    # send the random message when prompted
    R, S = # receive R and S

    assert (S < l)

    # generate H(R || A || M)
    h.update(binascii.unhexlify(R.encode()))
    h.update(pk)
    h.update(msg)

    hi = h.digest()

    # S = r + hi * s

    # populate min/max vectors, and first/last columns
    mins.append(0)
    maxs.append(B)
    col0.append(-1 * (bytes_to_long_le(hi) % l))
    coln.append(S)

# finish first and last columns, and min/max vectors
coln.append(B)

mins.append(B)
maxs.append(B)

# Create the min and max vectors
# These now are over rationals instead of integers
minvector = vector(QQ, mins)
maxvector = vector(QQ, maxs)    

# create the A matrix
a_helper = [[0] * (N+1) for j in range(N+1)]
for j in range(1,N):
    a_helper[j][j] = l
for j in range(N):
    a_helper[j][0] = col0[j]
for j in range(N+1):
    a_helper[j][N] = coln[j]

# the matrix has rationals now instead of only integers
A = matrix(QQ, a_helper)

# Compute LLL (LLL in sage operates on rows so you need to do some 
# transposes)
# and compute inverse transform
AL = A.transpose().LLL().transpose()
ALi = AL.inverse()

LHSt = ALi*minvector
RHSt = ALi*maxvector  

# Find midpoint
midpoint = ((RHSt) + (LHSt)) / 2

solutions = []

# Brute force around the midpoint to find integer points inside the
# parallelotope.
for j in range(2**(N+1)):
    consider = []
    for k in range(N+1):
        num = midpoint[k]
        if j&(1 << k): 
            num = floor(num)
        else:
            num = ceil(num)
        consider.append(num)

    # transform back to the original lattice (A' * x')
    considerVec = vector(ZZ,consider)
    check = AL*considerVec

    # check if the current point is inside the box
    correct = True
    for k in range(N+1):
        if (minvector[k] > check[k] or maxvector[k] < check[k]):
            correct = False
    if correct:
        solutions.append(check)

# list solutions (get a value of s)
for solution in solutions:
    s = l / B * solution[0]
    print(s)
```

We get one value of s: `3899083272976922877727946891354278904893743132859369983505696408961368609498`! 

Was the challenge set up so that there is only one value of s? Very interesting if so.


### Finishing the forge

Wait, what can we actually do with a value of s? The challenger gives us a message to sign: we need to generate some $(R, S)$ pair that passes `validate`. To sign a message, we need to know $r$ to compute $R = rB$, but $r$ is almost unpredictable since it is $H_2\left(H_1(k) || M\right)$. Actually, since $H_2$ is SHA-1, it could be possible via length extension to predict a value of $r$ if we controlled the message $M$. This would mean we try to break the [existential unforgeability](https://en.wikipedia.org/wiki/Digital_signature_forgery#Existential_forgery) of the signature scheme, but I digress. We don't control $M$, so this won't work.

Notice that in `validate`, we never actually validate the value of $R$! We never check if $R = H_2\left(H_1(k) || M\right)B$. This is great, because we can set $r$ to whatever we want, and $R = rB$. For the sake of simplicity, $r = 0$ and $R$ is the zero/identity point (for a Twisted Edwards Curve, this is (0,1) ). In compressed format, $R = 1$

Now, all we have to do is use our computed $s$ to calculate $S$: $S \equiv r + H_2\left(R || A || M\right)s \equiv H_2\left(R || A || M\right)s \mod{l}$. Send $(R,S)$ and that is our forged signature!

I couldn't actually find the flag since I solved this after the CTF finished, but this works with a local flag in a docker container!

### Some more observations

Remember how I said earlier that the differences between the two ends of the parallelotope should be small after LLL? What are the differences now?
```
0.9237529896491153
0.3087908297052731
-1.5771695467193385
1.9655031122546026e-22
-4.0900809726801086e-23
1.6461964516281455e-22
-2.0895236585878706e-22
1.2773255972177797e-22
-1.5919652305112045e-22
-9.966153132200175e-25
```

Woah, these differences are either around 1 or practically 0. That is so much better for enumerating lattice points in the parallelotope!

In fact, our parallelotope ended up so good that this is the value of $\hat{x}'$ (the integer point inside the parallelotope): `(0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0)`

We found such a good lattice, that LLL reduced so much that the target point had only two nonzero entries, an L1 norm of *2*. This is basically the best lattice we could have constructed for this problem.

#### Lattice Enumeration

While solving the challenge, I also came across a different (maybe more reliable) way to solve it. Instead of brute forcing integer lattice points around the midpoint of the parallelotope, we can feed the parallelotope into Sage's Polyhedron engine(s) and enumerate the lattice points inside of it. This can directly find the value of $\hat{x}'$. I found that Sage has two good engines for polytope lattice enumeration: [LattE integrale](https://www.math.ucdavis.edu/~latte/software.php) for integer polytopes and [normaliz](https://www.normaliz.uni-osnabrueck.de/) for rational polytopes (this is the one I used).

Lattice enumeration is an important program in integer linear programming, and I've been looking for libraries to help me do it (it looks really hard to do from scratch ;-;). Lattice enumeration is also very useful for these type of lattice cryptography challenges, offering exact solutions and the ability to find all possible solutions. The only problem is that again, if the lattice or the inequalities aren't formatted right, the polytope's dimensions become too large and searching it for lattice points becomes too expensive. This is why bringing the differences of the two ends of the polytope to be close to 0 is essential. Anyways, I finally can do it with Sage!

I wrote an alternate solve script to solve this challenge with lattice enumeration instead of brute forcing around the midpoint of the polytope. This works by first determining each of the $2^{n+2}$ vertices of the untransformed "box". Then, you can use $\mathbf{A}'^{-1}$ to transform all of these vertices into vertices of the transformed parallelotope. Then, you can input all of these vertices into Sage's `Polyhedron` class, and call `P.integral_points()` to find its integral points. In this case, I again only find one integral point inside the parallelotope, consistent with past findings. Finally, you can transform the integral point with $\mathbf{A}$ and the first element will be $s$, after which you can solve the rest of the challenge.


## Solve scripts

### Regular solve script

```python
import os
os.environ["TERM"] = "xterm-256color"

from pwn import *
from Crypto.Util.number import *
import binascii
import hashlib
import random
import string

exe = ELF("./challenge")

context.binary = exe

def bytes_to_long_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def long_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder='little')

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 1337)

    return r

def main():
    c = conn()

    l = 2 ^ 252 + 27742317777372353535851937790883648493
    B = 2 ^ 160

    # note that this is not n as described earlier (sorry), N = n + 1
    N = 10

    # receive public key
    pk = binascii.unhexlify(c.recvline().decode().strip().split()[-1].encode())

    # set up min/max vectors, first and last columns of A
    mins = [0]
    maxs = [B]
    col0 = [B / l]
    coln = [0]

    for i in range(N-1):
        # generate a random string
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        msg = random_string.encode()

        # send the random string when prompted
        h = hashlib.sha1()
        c.recvuntil(b'> ')
        c.sendline(msg)
        R, S = c.recvline().decode().strip().split()[1:]

        S = bytes_to_long_le(binascii.unhexlify(S.encode()))

        assert (S < l)

        # generate H(R || A || M)
        h.update(binascii.unhexlify(R.encode()))
        h.update(pk)
        h.update(msg)

        hi = h.digest()

        # Si = r + hi * s

        # populate min/max vectors, and first/last columns
        mins.append(0)
        maxs.append(B)
        col0.append(-1 * (bytes_to_long_le(hi) % l))
        coln.append(S)
    
    # finish first and last columns, and min/max vectors
    coln.append(B)

    mins.append(B)
    maxs.append(B)

    # Create the min and max vectors
    minvector = vector(QQ, mins)
    maxvector = vector(QQ, maxs)   

    # create the A matrix
    a_helper = [[0] * (N+1) for j in range(N+1)]
    for j in range(1,N):
        a_helper[j][j] = l
    for j in range(N):
        a_helper[j][0] = col0[j]
    for j in range(N+1):
        a_helper[j][N] = coln[j]

    A = matrix(QQ, a_helper)

    # Compute LLL (LLL in sage operates on rows so you need to do 
    # some transposes)
    # and compute inverse transform
    AL = A.transpose().LLL().transpose()
    ALi = AL.inverse()

    LHSt = ALi*minvector
    RHSt = ALi*maxvector

   # Find midpoint
    midpoint = ((RHSt) + (LHSt)) / 2
    
    solutions = []

    # Brute force around the midpoint to find integer points 
    # inside the parallelotope.
    for j in range(2**(N+1)):
        consider = []
        for k in range(N+1):
            num = midpoint[k]
            if j&(1 << k): 
                num = floor(num)
            else:
                num = ceil(num)
            consider.append(num)

        # transform back to the original lattice (A' * x')
        considerVec = vector(ZZ,consider)
        check = AL*considerVec

        # check if the current point is inside the box
        correct = True
        for k in range(N+1):
            if (minvector[k] > check[k] or maxvector[k] < check[k]):
                correct = False
        if correct:
            solutions.append(check)

    # get a value of s
    for solution in solutions:
        s = l / B * solution[0]

    # we want to forge a signature now
    c.recvuntil(b'> ')
    c.sendline(b'')

    # get challenge message
    challenge_msg = c.recvline().decode().strip().split()[-1]
    c.recvuntil(b'> ')

    zeropoint = 1 # compressed format of (0,1) identity point
    R = long_to_bytes_le(zeropoint,32)
    R_hex = binascii.hexlify(R).decode()

    h = hashlib.sha1()

    # compute H(R || A || M)
    h.update(R)
    h.update(pk)
    h.update(challenge_msg.encode())

    hram = bytes_to_long_le(h.digest())

    # compute the forged signature and send it
    S = (s * hram) % l
    S_hex = binascii.hexlify(long_to_bytes_le(S, 32)).decode()

    forged = (R_hex + ' ' + S_hex).encode()
    
    c.sendline(forged)

    c.interactive()

if __name__ == "__main__":
    main()

```

### Solve script with lattice enumeration

```python
import os
os.environ["TERM"] = "xterm-256color"

from pwn import *
from Crypto.Util.number import *
import binascii
import hashlib
import random
import string

exe = ELF("./challenge")

context.binary = exe

def bytes_to_long_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def long_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder='little')

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 1337)

    return r

def main():
    c = conn()

    l = 2 ^ 252 + 27742317777372353535851937790883648493
    B = 2 ^ 160

    # note that this is not n as described earlier (sorry), N = n + 1
    N = 10

    pk = binascii.unhexlify(c.recvline().decode().strip().split()[-1].encode())

    # set up min/max vectors, first and last columns of A
    mins = [0]
    maxs = [B]
    col0 = [B / l]
    coln = [0]

    for i in range(N-1):
        # generate a random string
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        msg = random_string.encode()

        # send the random string when prompted
        h = hashlib.sha1()
        c.recvuntil(b'> ')
        c.sendline(msg)
        R, S = c.recvline().decode().strip().split()[1:]

        S = bytes_to_long_le(binascii.unhexlify(S.encode()))

        assert (S < l)

        # generate H(R || A || M)
        h.update(binascii.unhexlify(R.encode()))
        h.update(pk)
        h.update(msg)

        hi = h.digest()

        # Si = r + hi * s

        # populate min/max vectors, and first/last columns
        mins.append(0)
        maxs.append(B)
        col0.append(-1 * (bytes_to_long_le(hi) % l))
        coln.append(S)
    
    # finish first and last columns, and min/max vectors
    coln.append(B)

    mins.append(B)
    maxs.append(B)

    # Create the min and max vectors
    minvector = vector(QQ, mins)
    maxvector = vector(QQ, maxs)   

    # create the A matrix
    a_helper = [[0] * (N+1) for j in range(N+1)]
    for j in range(1,N):
        a_helper[j][j] = l
    for j in range(N):
        a_helper[j][0] = col0[j]
    for j in range(N+1):
        a_helper[j][N] = coln[j]

    A = matrix(QQ, a_helper)

    # Compute LLL (LLL in sage operates on rows so you need to do 
    # some transposes)
    # and compute inverse transform
    AL = A.transpose().LLL().transpose()
    ALi = AL.inverse()
    
    solutions = []

    # find all vertices of the "box" defined by the inequalities
    vertex_list = []
    for j in range(2**(N+1)):
        vertex = []
        for k in range(N+1):
            if j&(1 << k): 
                vertex.append(minvector[k])
            else:
                vertex.append(maxvector[k])

        vertex_list.append(vertex)
    
    # apply ALi to each vertex to find its LLL-transformed version
    transformed_vertex_list = []
    for i in range(2**(N+1)):
        vertex = ALi*vector(vertex_list[i])
        transformed_vertex_list.append(vertex)

    # Create a parallelotope with the transformed vertices
    # Output the number of integral points it contains
    # Output any integral points inside of it
    P = Polyhedron(vertices = transformed_vertex_list, backend='normaliz')
    print(P.integral_points_count())
    x = P.integral_points()
    for v in x:
        solutions.append(vector(v))    
    print(solutions)

    # determine s
    for solution in solutions:
        s = l / B * (AL * solution)[0]

    # we want to forge a signature now
    c.recvuntil(b'> ')
    c.sendline(b'')

    # get challenge message
    challenge_msg = c.recvline().decode().strip().split()[-1]
    c.recvuntil(b'> ')

    zeropoint = 1 # compressed format of (0,1)
    R = long_to_bytes_le(zeropoint,32)
    R_hex = binascii.hexlify(R).decode()

    h = hashlib.sha1()

    # compute H(R || A || M)
    h.update(R)
    h.update(pk)
    h.update(challenge_msg.encode())

    hram = bytes_to_long_le(h.digest())

    # compute the forged signature and send it
    S = (s * hram) % l
    S_hex = binascii.hexlify(long_to_bytes_le(S, 32)).decode()

    forged = (R_hex + ' ' + S_hex).encode()
    
    c.sendline(forged)

    c.interactive()

if __name__ == "__main__":
    main()
```
