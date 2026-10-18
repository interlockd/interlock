# Performance

Interlock sits in front of every tool call, so it has to be cheap. Measure it on your own machine with:

```sh
interlock bench            # add --json out.json to keep the numbers
```

`bench` starts a private daemon in a temporary home (your audit log is not touched) and reports p50 / p95 / p99 in milliseconds for each path.

## Results

Interlock 0.1.1 (unreleased), Apple M4 Pro, macOS, Python 3.12:

| Path | What it measures | n | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|
| decide | the decision pipeline alone, over the whole rule corpus (attack and benign cases, every pack), including the hash-chained audit write | 783 | 1.17 | 1.87 | 2.61 |
| probe 4 KB | a post-action decision on a 4 KB tool result: the local injection probe plus the audit write | 200 | 6.07 | 8.46 | 12.99 |
| http | one hook call to the daemon over loopback HTTP, as an agent's hook delivers it | 300 | 4.87 | 8.46 | 16.24 |
| shim (tcp) | the full hook path an agent pays: the POSIX `sh` shim, `curl`, the daemon, over TCP | 100 | 92.49 | 149.78 | 213.25 |
| shim (unix) | the same over the daemon's 0600 Unix socket | 100 | 93.67 | 215.43 | 352.82 |
| floor | `sh` + `cat` + `curl` to the health endpoint, no decision | 100 | 89.13 | 161.42 | 213.56 |

## Reading the numbers

- **Decisions take about a millisecond.** The deterministic rules, the shell decomposer and the audit write together take 1.2 ms at p50. That is the "~2 ms per decision" figure, and p99 stays under 3 ms.
- **The hook shim mostly costs process spawn.** On this machine, starting `sh` and `curl` with no decision at all (the floor row) takes about as long as the full shim. Interlock adds the http row, about 5 ms. Process start-up varies a lot between machines. Endpoint security agents that inspect every `exec` make it much slower, so measure on yours.
- **Post-action is slower than pre-action** because the injection probe scans the whole result (up to 20,000 characters). An agent waits for this after the tool has already run, not before.
- **The optional model is not in these numbers.** With `judge` or a classifier enabled, ambiguous cases add the model's latency. The deterministic path still answers first, so clear cases never wait for the model.

## Timeouts and fail mode

The shim gives the daemon 1.5 s before a tool runs (`INTERLOCK_PRE_TIMEOUT_MS`) and 2.5 s after (`INTERLOCK_POST_TIMEOUT_MS`). Both are hundreds of times the measured p99. A call that times out is handled by the fail mode. It fails open by default, and refuses the call if `fail_mode.default` is `closed`. Every such call is logged to `~/.interlock/hook.log`, and `interlock doctor` reports it.
