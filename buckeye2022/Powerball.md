# Writeup
Examine the source code. We want to figure out what generates the numbers on the powerballs on the [website](https://powerball.chall.pwnoh.io/).
```js
function seedToBalls (n) {
  const balls = []
  for (let i = 0; i < 10; i++) {
    balls.push(Number(n % 100n))
    n = n / 100n
  }
  return balls
}
```
This method takes in a number n and uses the last 2*10 digits from n to display onto the website. So, we want to figure out what n is to determine what the correct powerball is.
```js
setInterval(() => {
  seed = nextRandomNumber()
  winningBalls = seedToBalls(seed)
  lastLotteryTime = Date.now()
}, 60 * 1000)
```
This tells us that a seed is passed into the seedToBalls method. Seeds are determined with the nextRandomNumber method():
```js
function nextRandomNumber () {
  return (multiplier * seed) % modulus
}
```
where
```js
const modulus = crypto.generatePrimeSync(128, { safe: true, bigint: true })
const multiplier = (2n ** 127n) - 1n
```
We don't know what the modulus is, but we know the multiplier. Let $m = modulus$ and $a = multiplier$. The next powerball seed will be $S_{n+1} ≡ aS_{n} \left(\textrm{mod }m\right)$. Thankfully, the full seed (not just the last 20 digits) are leaked to us in the website's console (inspect element → console). For example:
![Image](https://user-images.githubusercontent.com/42781218/200150250-1e8da4bb-351e-46c0-8ea0-f78641045293.png)
So, we are able to get a few values in the sequence generated by nextRandomNumber. This method is called a linear congruence generator. Our goal is to find the next seed given a current seed. To do this, we need to know the modulus m. I'll use a strategy based on [this Stackexchange post](https://imgur.com/a/RrxEU). 
$$\eqalign{S_{n+1} \equiv aS_n \left(\textrm{mod }m\right) \textrm{ and } S_{n+2} \equiv a^2S_n \left(\textrm{mod }m\right)\cr Z_n = S_{n+2}S_n - S_{n+1}^2 \equiv S_n\left(a^2S_n\right) - \left(aS_n\right)^2 \equiv 0 \left(\textrm{mod }m\right)\cr}$$
So, $Z_n$ is always a multiple of m. If we generate several values of Z, and take their GCD, we are very likely to get m. Once we find m, compute $aS_n \left(\textrm{mod }m\right)$ where $S_n$ is the current seed to find the next seed. Then, find the numbers to input into powerballs by reusing the `seedToBalls()` method (or implement it yourself in your preferred programming language). Here is the Python script I used to solve the problem.
```py
#a series of consecutive seeds
nums = [257409066671949985351617612750114265884,68603802263795555544881332070057637953,173661655731435739553611354559065411297,9386921835783678611693775477561382788]

#generate a list of Z values and find their GCD
Zs = []
for i in range(len(nums)-2):
        Zs.append(nums[i]*nums[i+2]-nums[i+1]*nums[i+1])
m = math.gcd(*Zs)
#print(m)

#select the current seed and determine the next seed
curr = nums[-1]
nex = (mult*curr)%m
#print(nex)

#generate output to enter into the powerballs
out = ''
for i in range(10):
        out+=str(nex%100)+' '
        nex//=100
print(out)
```