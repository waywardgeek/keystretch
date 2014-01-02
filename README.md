keystretch
==========

My attempt at an efficient memory-hard key stretching algorithm based on scrypt

Goals
-----

- Reduce ability to make time/memory trade-off (TMTO) in favor of higher area*time for attacker
- Increase speed with faster hashing, increaseing area*time
- Start with 4096 + N*1024 rounds of SHA256-PDKDF2 traditional key derivation, and improve from there
- Operate well in a deniable mode, meaning only random parameters like salt can be stored
- Benefit from 64-bit CPU widths without trashing 32-bit performance

We simultaneously fill memory and hash into the derived key.  When we're done filling
memory, we're done.  This is more friendly for users who want to pick a time to run,
rather than specifying the memory.  Threads will write blocks that are a multiple of their
threadId.  Threads will read randomly from all prior blocks, and will spin-lock if another
thread is still generating it.

This reduces flexibility in time-memory trade-off, which is bad for the attacker.  Credit
for this idea goes to Alexandar on this thread:

    http://www.openwall.com/lists/crypt-dev/2013/12/19/1

Scrypt relies on Salsa20/8, which is a well known algorithm.  It's fast, but still several
times slower than just filling memory with a counter.  At the same time, there seems to be
little need for such a secure RNG.  It has only three goals, AFAIK:

- It should generate data efficiently on a CPU, so we can make memory bandwidth the
  bottleneck, just like it is for an attacker
- It should not allow an attacker easily to compute V(i), without first computing
  V(0)...V(i-1).  Here V is memory and i is the ith memory location.
- It should have a large state, so the attacker can't just cache RNG states, and must
  fill memory instead.

Faster hashing should make use of 64-bit data paths without killing the performance on
32-bit machines.  It should focus on speed over proven security, but make it simple to
prove property 2.

To reduce/eliminate dependence on saved parameters other than salt, the hash data is
independent of the number of threads used.  There is a maximum of 16 threads, and the data
is be computed assuming 16 threads.

Since we fill memory as we go, in addition to the salt, we could store a stop parameter,
of say 128 bits or more.  When we see the stop parameter matches a thread key, we would
stop hashing.  This has not been implemented, but it is an intended mode of the algorithm.
This could be particularly usefule for TrueCrypt or any other tool which supports
deniability.

Speed comparison to script
--------------------------

Here's the output on my linux box when I put a timer around scrypt in scrypt enc:

scrypt-1.1.6> ./scrypt enc foo bar
Please enter passphrase:
Please confirm passphrase:
N:262144 r:8 p:1
0.966984
scrypt-1.1.6> ./scrypt enc foo bar
Please enter passphrase:
Please confirm passphrase:
N:262144 r:8 p:1
0.963024
scrypt-1.1.6>

When r is 8 (as it always is), N is in KB.  So, scrypt takes 0.96 seconds and uses 1/4 GB.

Here's the output from keystretch on the same machine.  It hashes 2GB in .92 seconds.
Both scrypt and keystretch runs were single-threaded, running on my medium-end Core i7
Arch Linux server.  Keystretch uses the sha256.c file from scrypt to reduce timing
variations due to code implementation.

keystretch> ./run
058C310ECEED97BE284EBF51F7DED47EB436EFBC11EE7B566A933EE56C4F3F31
real    0m0.930s
user    0m0.840s
sys     0m0.090s
keystretch> ./run
058C310ECEED97BE284EBF51F7DED47EB436EFBC11EE7B566A933EE56C4F3F31
real    0m0.918s
user    0m0.850s
sys     0m0.060s

The speedup factor per unit memory is 8.3X, even though keystretch performs 4096 rounds of
SHA-256 hashing of the password before using this intermediate derived key to hash memory.

To run dieharder, use the dieharder.header and data generated with the printf statements
commented in, and run:

dieharder -a -g 202 -f foo
