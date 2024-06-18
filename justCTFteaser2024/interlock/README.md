# interlock

- Category: crypto
- Final point value: 355
- Number of solves: 11
- Solved by: gmo_goat & mouthon

A crypto chall where we had a timed based secure exchange to defeat in a MITM position.

## Figuring out what to do

The challenge was marked as pwn/crypto, at first we looked at the environement which seemed very protected (nsjail and all), the usual pwn setup, despite that the main entrance point is [task.py](./chall/task.py). We are in a position of man in the middle (between Alice and Bob as Eve) and we are given a nice template [eve.py](./chall/eve.py) to do so.

At first we though the title `interlock` suggested a misuse of mutex or something, but we quickly turned our attention to the timer binary wich was used to handle a crucial part of the key/encrypted data exchange : __timing__.

## Playing around

I was mostly responsible for the crypto part and this key/data exchange didn't seem to but much of a problem to MITM at first, just :

    Make a spoofed Alice key A' a spoofed Bob key B' and answer Bob and Alice with their opposite spoofed keys.

But here we have a problem, when first sending $c_1$ to Bob we don't know the corresponding $x_1$ until 4 seconds later Alice gives it but the problem is that we need to wait for Bob to respond and here Alice will time out...

And even though it seem like we could just sign whatever we want and not wait for the correct $x_1$, we can't because at the end of the exchange we're expecting values of $x_1$ and $x_2$ to match...

If we don't spoof the keys then we get $x_1$ and maching keys but not way to decipher $x_2$, also the fancy and complex pre-made primitives made me think this is not really the kind of crypto we're supposed to attack up frond and the pwn tag really meant that something was wrong with the binary.

## Dirty C++

C++ is a pain to rev, the first thing we wanted to understand was why we get different dates everytime and it seemed suspiciously close to a new year.
We looked a bit into the decompilation output in ghidra but what ended up showing the problem was trial and errors and by testing by hand, mouthon noticed we had and extra second at the exact time when passing to a new year. This is exactly what we needed to get the time to recieve Alice first 2 messages (with $x_1$ in cleartext) and perform the MITM with spoofed keys.

## Path to flag

- Use the gift of the time to calculate how much time till new year
- Wait till we get there and start Alice and Bob at the right time such that the extra seconds falls into the time Alice is measring time for timeout
- Make sure everything is corresponding all the way to the end of the transmission and use the fact that we own the spoofed keys to decipher x2
