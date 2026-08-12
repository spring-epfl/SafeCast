# Realistic Receiver Benchmark Results

Results from `realistic_receiver.rs`: the three keying granularities
(epoch-only/frame-level/packet-level) measured on the "reorder-capable"
receiver (`ReceiverKeyManager`) instead of the ideal in-order delivery 
of `granularity_throughput_ideal`.
Pipeline per run: a simulated sender produces the encrypted stream
in send order. The network model turns the send times into an arrival order
(jitter, loss, dual-path merge, all driven by one RNG seed). The bench
feeds the receiver in exactly that arrival order and times only the
decryption time, while collecting stats.

## Outline

We first describe the setup of this benchmark. We then present the main results, 
a timing table of all six runs. The analysis of the results follows in six steps. 
Sections 1 and 2 show what disturbance does to throughput and to latency. Section
3 explains both effects by attributing each packet's decryption cost to
the work that this decryption performed. Section 4 measures how much key history the receiver needs.
Section 5 turns that into the forward-secrecy tradeoff. Section 6 validates the bench
against the ideal benchmark to make sure the bench is not broken. 
At the end, we point to the raw output files and the commands that reproduce every run.

## Setup

"Clean" runs use a single path with zero jitter and zero loss (i.e. in-order delivery).

"Disturbed" runs use our assumed facility network:
* two paths (ST 2022-7) whose transit times differ by 2 ms
* per path, uniform 0-100 µs jitter
* per path, 1e-5 loss: each packet travels as one copy per path, and
  each copy is lost independently with probability 1 in 100,000. A packet
  is gone only if both its copies are lost. The 1e-5 is the upper bound
  on loss for our setting.
  Source: https://www.itu.int/rec/T-REC-Y.1541 (Table 3)

These numbers are chosen for our specific setting. However, each is a CLI flag, 
and hence open for configuration.

All runs use the same receiver limits: key window K = 512 (the receiver
keeps the last 512 generation keys), seek cap 4,096 (the most keys one
packet may demand deriving at once), replay window 512 packets. What
happens when K shrinks is measured in section 4. The seek cap never
mattered in any run: the largest jump any packet demanded was 18 keys 
and no packet was ever refused (drops_seek_cap = 0).

## Main results (standard 1424 B MTU, per `unprotect` call)

| granularity | condition   | mean ns | p50  | p99  | p99.9 | Gbps  |
|-------------|-------------|---------|------|------|-------|-------|
| epoch       | clean       |   325.2 |  333 |  458 |   500 | 35.72 |
| epoch       | disturbed   |   306.4 |  292 |  416 |   459 | 37.92 |
| frame       | clean       |   312.6 |  292 |  416 |   459 | 37.16 |
| frame       | disturbed   |   300.9 |  292 |  375 |   667 | 38.60 |
| packet      | clean       |  1121.4 | 1125 | 1250 |  1667 | 10.36 |
| packet      | disturbed   |  1062.4 |  625 | 4375 |  5792 | 10.93 |

The columns:

- **p50/p99/p99.9** are percentiles of the per-call decrypt time: the
  time that 50%, 99%, and 99.9% of the calls stayed at or below. p50 is
  the median, p99 and p99.9 describe the slowest 1%
  and 0.1% of packets (the "tail" of the distribution). We record them
  because the mean hides rare slow packets, and it is exactly those
  that break availability.
- **Throughput** = wire bits/mean. Since the receiver is serial (one
  decrypt at a time), throughput is 1/latency by definition.

## Reading the numbers

### 1. Effect of disturbance on throughput

Sustained decrypt throughput at 1424 B:

- epoch: 35.7 Gbps clean, 37.9 Gbps disturbed
- frame: 37.2 Gbps clean, 38.6 Gbps disturbed
- packet: 10.4 Gbps clean, 10.9 Gbps disturbed

Two observations:

- Packet-level keying costs ~3.5x: it sustains ~3.5x fewer packets
  per second than the other two granularities. Frame-level, by contrast,
  is indistinguishable from epoch-only: its 275 rekeys (one per frame)
  amortize to ~0.4 ns per packet, which is invisible.
- Disturbance does not reduce throughput: disturbance adds no crypto
  work, as every key is derived exactly once whatever the arrival order.
  Reordering only changes which packet pays the cost, which we discuss 
  further in section 3.

### 2. Effect of disturbance on latency

- **Epoch:** no significant change.
- **Frame:** only the extreme tail moves: p99.9 increases from 459 to
  667 ns. The expensive packets are the *flip-flops*: a straggler from
  the previous frame arrives after the receiver has already moved on to
  the current frame, so the receiver must swap the previous frame's key
  back into the cipher to decrypt it. The next packet then needs
  the current frame's key swapped back in again, so both calls pay an
  extra key install on top of the normal decrypt. The bench's per-call
  classification (section 3) counts them: 1,593 straggler calls at
  ~492 ns mean, versus ~300 ns for a normal packet, plus roughly as many
  swap-back cases. Together ~3,200 of the 950,000 measured calls
  (~0.3%) are made expensive by flip-flopping. p99.9 is the cost at the border of the slowest
  0.1% of calls. Since 0.3% > 0.1%, the slowest 0.1% consists entirely of
  flip-flop calls.
- **Packet:** the whole distribution changes. The median goes down and
  the tail goes up. In the clean run, every call does the same work. It
  derives exactly one key and decrypts, so every call costs about
  1,121 ns (p50 = 1125, p99 = 1250).
  Under disturbance there are two kinds of calls, counted by the
  per-call classification of the next section. 72% of the calls belong to
  packets that arrive late, after a jump-ahead call already derived
  their key (687,767 of the 950,000 measured calls, from the class
  table of section 3). In this case we just read the key and decrypt.
  It costs 631 ns, which is cheaper than any clean call. The other 28%
  (262,233 calls) are the jump-ahead calls themselves. Each of them derives every key
  that its jump skipped, which costs 2,195 ns on average. This explains 
  the two factors in the table:  1) the median drops from 1125 to 625 because 
  the cheap kind makes up 72% of all calls, so the call in the middle of the distribution is a cheap
  one, and 2) p99 goes from 1250 to 4375 and p99.9 from 1667 to 5792
  because the slowest calls are now the "deep" jump-ahead calls. The
  total work is the same in both runs. Disturbance only redistributes that work, 
  making most calls cheaper and a few much more expensive.

### 3. Path attribution

The percentages and per-kind costs used in sections 1 and 2 come from
this instrumentation. The bench classifies every successful decrypt by
comparing the generation that the call decrypted under against the
highest generation seen so far. A call above that maximum is an
"advance": it derived new keys to catch up. A call at the maximum is a
"current", which means it reused the newest key. A call below it is a "straggler",
a late packet served by an old key from the ring. The decrypt
times are collected per class, so each kind of call gets its own timing
statistics.

**Packet level.** Per-class timing of the disturbed run. All counts are
over the 950,000 measured calls (the 1,000,000 minus the
first 50,000 as warmup).

| class     | meaning                          | n       | mean ns | p99 ns |
|-----------|----------------------------------|---------|---------|--------|
| advance   | derived new key(s) (catch-up)    | 262,233 | 2,194.8 |  5,167 |
| straggler | late packet, reuses old key      | 687,767 |   630.6 |    792 |

At packet level every generation is a single packet, so the "current"
class is empty here.

We additionally split the advances by their depth (i.e. the number of
keys that the one call derived) to answer one question: are the slowest
calls really the ones that derive many keys at once, or does the tail
come from something we cannot explain?

| depth | n      | mean ns | | depth | n     | mean ns |
|-------|--------|---------|-|-------|-------|---------|
| 1     | 55,500 |   1,128 | | 10    | 2,963 |   4,852 |
| 2     | 49,701 |   1,528 | | 11    | 1,613 |   5,247 |
| 3     | 42,461 |   1,926 | | 12    |   742 |   5,646 |
| 4     | 34,332 |   2,327 | | 13    |   341 |   6,058 |
| 5     | 27,006 |   2,776 | | 14    |   136 |   6,428 |
| 6     | 19,468 |   3,181 | | 15    |    20 |   7,029 |
| 7     | 13,635 |   3,580 | | 16    |    24 |   7,203 |
| 8     |  8,868 |   3,970 | | 17    |     5 | (9,284) |
| 9     |  5,417 |   4,446 | | 18    |     1 | (8,583) |

(Depths 17 and 18 are in parentheses because 5 and 1 samples are too
few to mean anything.)

The cost grows linearly with the keys derived, about 405 ns per key.
The slowest calls are exactly the deep advances. To see that, take the
disturbed packet row of the "Main results" table and locate its tail
values against this table. The slowest 1% of all calls must be the calls of depth 9 or more, 
because the n column for depths 9 to 18 sums to 11,262 calls and 11,262 / 950,000 = 1.2%.
The measured p99 is consistent with that: 4,375 ns sits between the
depth 8 and depth 9 means (3,970 and 4,446 ns). The same works for the
p99.9: the slowest 0.1% must be the calls of depth 12 or more (depths
12 to 18 sum to 1,269 calls, and 1,269 / 950,000 = 0.13%), and the
measured p99.9 of 5,792 ns sits between the depth 12 and depth 13
means (5,646 and 6,058 ns).

**Frame level.** The same classification for the frame-level disturbed
run:

| class     | n       | mean ns | p99 ns |
|-----------|---------|---------|--------|
| advance   |     261 | 1,235.5 |  1,750 |
| current   | 948,146 |   300.3 |    375 |
| straggler |   1,593 |   491.5 |    709 |

Here the "current" class dominates: 99.8% of the calls simply reuse the
running frame's key at about 300 ns. The 261 advances are at the frame
boundaries. The 1,593 stragglers at ~492 ns are the flip-flop packets
discussed in section 2.

### 4. How much key history do we need?

K is the number of generation keys the receiver keeps. A late packet
can only be decrypted if its key is still among those K, so K decides
how much lateness the receiver tolerates. At the same time every kept
key is exposure in case the receiver is compromised (discussed in section 5), 
so we want the smallest K that avoids losses. To find it, we first repeated the
packet-level disturbed run for a range of K values and recorded the
keying-loss rate (i.e. the fraction of delivered packets that the
receiver dropped because their key was already deleted).

| K   | keying loss        | | K   | keying loss      |
|-----|--------------------|-|-----|------------------|
| 4   | 5.87e-1 (587,302)  | | 128 | 1.00e-4 (100)    |
| 8   | 4.04e-1 (404,118)  | | 256 | 1.00e-4 (100)    |
| 16  | 7.28e-2 (72,796)   | | 400 | 1.00e-4 (100)    |
| 24  | 1.00e-4 (100)      | | 448 | 2.00e-5 (20)     |
| 32  | 1.00e-4 (100)      | | 456 | **0**            |
| 64  | 1.00e-4 (100)      | | 512 | 0                |

To interpret this table, we translate delays into packet positions. The sender
emits one packet every 4.578 µs, because a frame consists of 3,640
packets, a frame lasts 16.67 ms, and 16.67 ms/3,640 = 4.578 µs. Two
things make a packet arrive late. First, jitter delays it by at most
100 µs, and 100 µs/4.578 µs ≈ 21, so at most 21 later packets can
overtake it. Second, when a packet's path-A copy is lost, its path-B
copy arrives in its place 2 ms later, and 2 ms/4.578 µs ≈ 437, so
such a packet arrives about 437 positions late (up to 455 with jitter
on top). These two numbers, 21 and 437, produce the three regions of
the table.

- **Below K ≈ 24 the losses are catastrophic.** Ordinary jitter
  reorders most packets a little. The network simulation counts the
  disorder it produces (saved in the raw output files under
  `../realistic_receiver/`):
  724,046 of the 1,000,000 packets (72%) arrived out of order, with a
  median lateness of 5 positions and a p99 of 19. A key window
  below these latenesses therefore loses a lot of packets.
- **From K = 24 to K = 448 the loss rate is flat at 1e-4.** The
  only packets still failing are the 100 path-B rescues, which arrive
  437 to 455 positions late. No K between the jitter scale (21) and the
  dual-path scale (437) can save any of them, which is why 400 consecutive
  K values change nothing.
- **The loss reaches zero at K = 456, the measured worst lateness (455)
  plus one.** This is the general sizing rule: K must cover the worst
  lateness.

The same experiment at frame level shows what coarser generations buy. At
K = 1 the receiver keeps only the current frame's key, and we
measure 1,681 lost packets. Those are exactly the late packets that
arrive after the receiver already moved to the next frame, so their own
frame's key was already deleted. At K = 2 the loss is zero, because the
worst lateness of 455 packets is shorter than one 3,640-packet frame,
so a late packet can be at most one frame behind. The same network
disorder therefore needs 456 kept keys at packet level and 2 at frame
level.

### 5. The forward-secrecy tradeoff

Keeping old keys is not free in security terms. An attacker who
compromises the receiver obtains all K stored keys, and each stored key decrypts 
one generation of recorded traffic. How much traffic that is depends exactly on the granularity. 
A packet-level key unlocks one packet. A frame-level key unlocks a whole 3,640-packet
frame. The epoch key unlocks the entire epoch. The exposure of a
configuration is therefore K multiplied by the traffic behind one key.
Using the values measured in section 4:

| granularity | K for zero loss | exposure if compromised             |
|-------------|-----------------|-------------------------------------|
| epoch       | 1               | the whole epoch                     |
| frame       | 2 (frames)      | 7,280 packets ≈ 33 ms of video      |
| packet      | 456 (packets)   | 456 packets ≈ 2.1 ms of video       |

Packet-level keying keeps 456 keys and frame-level keeps only 2, yet
packet-level exposes about 16 times less traffic (456 packets against
7,280), because each of its keys unlocks so little. This is the central
tradeoff of the whole evaluation: packet-level keying buys about 16
times finer forward secrecy at about 3.5 times the per-packet cost of
section 1.

### 6. Validation: the clean runs must reproduce the ideal benchmark

This bench is new machinery, so to trust its numbers we check it
against the `granularity_throughput_ideal` benchmark. A
clean run delivers every packet in order, which is exactly the scenario
that the ideal benchmark measures. The two must therefore agree, up to
one known difference: the ideal benchmark decrypts with the simple
in-order receiver, while this bench always uses the reorder-capable
receiver, which does some bookkeeping on every packet even when nothing
is reordered.

| granularity | ideal bench (fig9 data) | this bench, clean | overhead |
|-------------|-------------------------|-------------------|----------|
| epoch       | 290.9 ns                | 325.2 ns          | +34 ns   |
| frame       | 301.4 ns                | 312.6 ns          | +11 ns   |
| packet      | 1046.7 ns               | 1121.4 ns         | +75 ns   |

The two benchmarks agree up to that receiver bookkeeping (11 to 75 ns
per call).

## Outputs

The complete reports of every run quoted in this document can be found
in `../realistic_receiver/`:

- `{epoch,frame,packet}_{clean,disturbed}.txt` hold the six main runs,
  one full report each (network counters, receiver counters, path
  attribution, timing).
- `k_sweep_packet.txt` and `k_sweep_frame.txt` hold the K sweeps of
  section 4, with the receiver outcome and keying-loss line of every K
  value.

## Reproduction

```
# the disturbed packet-level run:
cargo bench -p safecast-core --bench realistic_receiver -- --granularity packet --packets 1000000

# the clean packet-level run (used in the validation of section 6)
cargo bench -p safecast-core --bench realistic_receiver -- --granularity packet --packets 1000000 \
    --jitter-ns 0 --loss 0 --single-path

# one K of section 4:
cargo bench -p safecast-core --bench realistic_receiver -- --granularity packet --packets 1000000 \
    --key-window 24
```

Swap `--granularity` to frame or epoch for the other runs, and
vary `--key-window` for the other K values.
