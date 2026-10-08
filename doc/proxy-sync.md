# Push Subscription Synchronization

Revision-aware clients require an updated proxy. Old clients remain supported:
requests without `sync` retain the original subscription response format.

## Validation and Snapshots

A `SUBSCRIBE /key/<hash>` request contains the existing push registration fields
and a `sync` object. An empty object requests a full snapshot. A synchronized
client instead supplies its last reconciled token:

```json
{"sync":{"epoch":"<listener-epoch>","revision":7}}
```

The epoch is unique to the server-side listener. New and restored listeners get
fresh epochs. Each addition, edit, or expiration reported by the DHT listener
increments its revision. Epoch/revision state is not restored from disk.

When the token matches, the response contains only a completion record. Otherwise,
the response contains newline-delimited value objects followed by this record:

```json
{"sync":{"epoch":"<listener-epoch>","revision":8,"snapshot":true,"complete":true}}
```

The listener retains its current values, including edits and expirations, under
the same mutex as its revision. The server copies both atomically; it does not
run a GET for a synchronization request. New listeners wait for initial readiness
before responding. `snapshot:false` means validation found the client's cache
unchanged. Successful responses always have `complete:true`; initial search
failure returns HTTP 503. The deprecated `retry` field is not used. Every
subscription request renews the lease, independently of whether values are sent.

Clients buffer snapshot values and reconcile only after a valid completion
record and successful HTTP framing. Reconciliation delivers new values and
higher-sequence edits, suppresses duplicates and older versions, and expires
cached IDs absent from the snapshot. Failed or invalidated responses never
remove cached values. Snapshot deletion is authoritative and does not depend
on wall-clock timestamps.

## Push Ordering and Recovery

Value pushes include string fields `epoch` and `revision`. A push no newer than
the reconciled revision is ignored. Revisions must be unsigned decimal integers
without signs, whitespace, trailing characters, or overflow. A contiguous
expiration revision removes the listed IDs locally without a download. The
`expired:"true"` field identifies batched expirations using `ids`; the original
single-value `exp` field remains supported. Other same-epoch changes and revision
gaps require a cached snapshot. Unknown epochs first validate against the proxy,
so delayed pushes from old epochs do not force a value download. Revisions cover
edits as well as additions and deletions.

Clients allow one sync request per listener and coalesce overlapping triggers.
Request generations reject callbacks from superseded requests. Completion state
changes run under the listener's owning lock after checking the generation.
Same-epoch push observations can invalidate an older snapshot. Confirmed retired
epochs are remembered in a bounded, push-token-scoped set; other unknown epochs
are validated without changing cached values. Returning to an earlier push token
remains valid.
Token rotation during a pending request is applied after that request completes.
Clients require an updated proxy server. Value pushes without both epoch and
revision are malformed and return `Error`; they do not mutate the listener cache
or trigger synchronization requests. The proxy adds these fields independently
of whether its upstream DHT peers support version-2 native LISTEN.
Pushes for another client session return `IgnoredWrongSession` without changing
subscriptions, cached values, or connectivity state. Their application-level
purpose is to wake the mobile app; session creation and desired subscriptions
are independent actions. A new session requests its own full initial snapshot
and does not inherit synchronization state from the rejected push.

Connectivity changes and existing lease refreshes validate the last reconciled
token; unchanged data is not downloaded again. Successful lease renewal alone
does not clear pending recovery. Failed recovery retries use the existing lease
timer with exponential delays from one to sixty seconds; successful recovery
restores the normal lease schedule. Stale and malformed responses also use this
backoff, rather than retrying immediately. Each subscription request has a
30-second steady-clock deadline covering DNS, connection, and response body
receipt. Expired requests release the in-flight slot and enter recovery. No
healthy-state polling timer is added.

Without another event or polling, a silently dropped final push cannot be
detected immediately. The next connectivity validation or existing lease refresh
detects a revision mismatch. Guarantees concern reconciliation with the proxy's
observed DHT state, not linearizable global DHT storage.

## Listener Readiness

The existing four-argument `listen` API remains available. The new overload adds
a one-shot `DoneCallbackSimple` as its fifth argument:

```cpp
runner.listen(key, valuesCallback, {}, {}, readyCallback);
```

`readyCallback(true)` follows completed search/listener synchronization for each
enabled address family. Version-2 native sources complete after initial delivery
and contiguous updates through their observed high-water mark. Legacy sources
complete when LISTEN registration is acknowledged; initial values can arrive
after readiness. Isolated families with no peers are ready after delivering local
values. Initial search or registration failure reports `false`; cancellation
does not promise a callback.
This is an initial completion notification, not a global consistency guarantee.
It does not start a GET or add polling. Attaching to a synchronized cache delivers
cached values before notifying readiness.
Mixed-version and entirely legacy networks can initialize successfully without
GET fallback or polling. A legacy acknowledgment confirms registration, not
complete baseline delivery or absence of values. Late values remain ordinary
listener updates: the proxy advances its revision and push clients reconcile
through the existing subscription path. A client snapshot is authoritative for
the proxy's observed cache, not proof of a complete upstream DHT baseline. A
legacy update never received by the proxy cannot be detected by proxy revision
validation. Proxy readiness callbacks run outside the client's search lock;
cancellation suppresses queued notifications.

Streaming proxy clients request `/key/<hash>/listen?sync=1`. Updated proxies send
`{"sync":{"complete":true}}` after initial values, or `complete:false` on initial
failure. Requests without this opt-in retain the original stream format.

## Native Initial Delivery

Native clients request LISTEN version `ve:2` with an `ls` tuple:

```text
[registration, epoch, sequence, snapshotEnd]
```

The registration is a fresh nonzero client nonce; a LISTEN request sends zeros
for the other fields. The server explicitly acknowledges version 2, assigns a
nonzero stream epoch, and declares the number of initial UPDATE batches in
`snapshotEnd`. An empty baseline declares zero batches. Each UPDATE carries the
same registration, epoch, and snapshotEnd with a consecutive sequence starting
at one. The initial batches occupy sequences 1 through snapshotEnd; live changes
follow them. The acknowledgment's sequence is the server's current high-water
mark. All tuple fields are unsigned 64-bit integers.

The server registers the listener and serializes the initial batches on its DHT
thread. Existing UPDATE fragmentation and acknowledgments deliver each initial
value once per source registration on a loss-free connection. There is no
additional GET or second value download. Retries resend the same immutable
request bytes. Repeated registrations with the same nonce reuse the baseline;
healthy renewals return metadata only. Recreated sockets use a new nonce and
cannot accept the previous registration's updates.

Live updates, including edits, expirations, and refreshes, are sent immediately
while the baseline is in flight. The receiver buffers them until every declared
initial batch has been fully reassembled and validated. It then applies the
baseline followed by contiguous live changes in sequence order. Duplicates are
acknowledged without being applied again. Known sequence gaps prevent the cache
from being considered synchronized; retransmission can fill them. Initialization
or an unresolved live gap fails after 30 seconds and allows a fresh registration.

Batches contain at most 32 values and target the existing 56 KiB serialized-value
budget; individual larger values retain the existing fragment transport. The
receiver bounds buffered batches to 4096 and payload bytes to 64 MiB, and rejects
baselines exceeding its 4096-value cache capacity. Invalid version-2 values fail
the batch instead of being silently skipped. This design adds neither pacing
nor send windows. Per-peer baselines are coherent with their subsequent updates,
but do not provide an atomic snapshot of the entire distributed DHT.

Peers that do not explicitly acknowledge version 2 remain legacy listeners.
Their values are delivered normally and successful LISTEN acknowledgment
completes their best-effort initialization. No GET fallback or polling is added.
Legacy LISTEN acknowledgments may omit the token; clients retain the token
previously obtained during discovery and keep the listener socket open. A
version-2 acknowledgment must include its token and synchronization metadata.
The source records whether it uses legacy completion or a verified version-2
stream. An established version-2 stream cannot downgrade on a metadata-free
acknowledgment; invalid initialization and registration failures still report
failure.

## HTTP Transport Note

HTTP requests now report status code zero for transport errors and cancellation,
even if a 200 status was received before the failure. Cancellation also sets
`aborted`. EOF succeeds only when the HTTP parser confirms complete framing;
truncated content-length and chunked responses fail. Callers must not treat an
earlier status callback as proof that a response body completed successfully.