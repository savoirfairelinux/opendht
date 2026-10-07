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

`readyCallback(true)` follows delivery of initially observed values and completed
search/listener synchronization for each enabled address family. Isolated
families with no peers are ready after delivering local values. Initial search
or registration failure reports `false`; cancellation does not promise a callback.
This is an initial completion notification, not a global consistency guarantee.
It does not start a GET or add polling. Attaching to a synchronized cache delivers
cached values before notifying readiness.

Streaming proxy clients request `/key/<hash>/listen?sync=1`. Updated proxies send
`{"sync":{"complete":true}}` after initial values, or `complete:false` on initial
failure. Requests without this opt-in retain the original stream format.

## HTTP Transport Note

HTTP requests now report status code zero for transport errors and cancellation,
even if a 200 status was received before the failure. Cancellation also sets
`aborted`. EOF succeeds only when the HTTP parser confirms complete framing;
truncated content-length and chunked responses fail. Callers must not treat an
earlier status callback as proof that a response body completed successfully.