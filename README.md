# Analyzing cold request performance

Requires `derailed_benchmark` branch with `perf:stackprof_warmup` command added: [get it here](https://github.com/viraptor/derailed_benchmarks/tree/warmup-tests)

The command allows you to take a profile the difference between the initial request and the later ones.

# Finding the initial slowdown

The first request will normally do more work than the follow-up ones. One part of that is the things that the framework itself needs to initialize. For example starting the database connections, caching the schema, finding translations, etc. The other part is things that the application itself is doing. For example caching data from db queries which doesn't get refreshed for hours.

Some of these things can be moved to the bootup process so that it doesn't affect the real request.

This script identifies 3 kinds of time sinks present only in the initial request:
- framework-specific ones (for example initializing the methods on ActiveRecord models)
- view-caching related (time per view / partial is summed up)
- application-specific ones (explicit controller actions)

# Usage

First, the data collection needs to be run over multiple requests. The initial request profile is saved with suffix `.warm` and the follow-up ones with suffix `.cold.X`. For example:

```
for x in $(seq 1 10) ; do
  TEST_COUNT=10 PATH_TO_HIT=/ RAILS_ENV=production bin/derailed exec perf:stackprof_warmup
done
```

This will make 10 cold request and for each of them 10 warm requests. (110 profiles in total) If the initial requests take ~1 second, this should be enough. If they take much shorter time, use either more iterations, or set `INTERVAL=20` (instead of the default 100us).

Then, the profiles saved in `tmp/...` can be anaylsed. Run:

```
path_to/rails_cold_spots.py -k -m -t tmp
```

To get a breakdown like:
```
Average warmup time per request: 1953.5ms

Known time sinks:
application initiated queries                          :   5971,  30.6%,  597.1ms
ActiveRecord creating attribute methods on models      :   1832,   9.4%,  183.2ms
ActionDispatch building route cache                    :   1625,   8.3%,  162.5ms
...
```

The usual options mean:
- `-k` - classify known time sinks
- `-m` - remove common injected instrumentation, like NewRelic
- `-t` - identify templates

For further debugging, there's also:
- `-u` - try to merge one-off traces into bigger groups
- `-f` - remove line numbers and process files only
- `-v` - more verbose output
- `-o N` - from the unidentified traces, show the N most common ones
- `-l N` - when showing traces, list the top N frames only

# Current status

Alpha - it works, but the nice packaging is still coming

# License

Code distributed under Apache-2.0 license.
