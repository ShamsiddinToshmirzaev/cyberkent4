# BLS Orchestra — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme

BLS12-381, minimal-pubkey-size:
- secret `sk` (scalar), public `pk = sk·G1` (compressed G1, 48 bytes, hex).
- `H : message → G2` via RFC-9380 hash-to-curve with the domain tag `app_dst`
  (from `/info`), cofactor-cleared.
- signature `sig = sk·H(m)` (compressed G2, 96 bytes, hex).
- verify: `e(pk, H(m)) == e(G1, sig)`.
- same-message aggregate over a set: `apk = Σ pk_i`, `asig = Σ sig_i`,
  verify `e(apk, H(m)) == e(G1, asig)`.
- the approval message is `m = "setlist-approval-v1|" + title` (`app_prefix` in `/info`),
  hashed with `app_dst`.
- proof of possession (modern enroll): `pop = sk·H_pop(pk)` where `H_pop` hashes the
  compressed `pk` with `pop_dst`; verified `e(pk, H_pop(pk)) == e(G1, pop)`.

## Endpoints

### `GET /info`
`{ members:[{pubkey, committee, section, weight}], threshold, sections:[{name,base_weight}],
   provisional_section, target_title, app_dst, pop_dst, app_prefix }`

### `POST /legacy/import`  `{ "pubkey": "<hex G1>" }`
Registers a key with **no proof of possession**. The key is forced to
`section = provisional`, `weight = 0`, deduped by pubkey. Returns the stored record.

### `POST /enroll`  `{ "pubkey": "<hex G1>", "section": "...", "pop": "<hex G2>" }`
Modern path: verifies the proof of possession before registering (weight 0). A bad
or mismatched `pop` is rejected.

### `POST /approve`  `{ "title", "pubkeys":[<hex G1>...], "asig":"<hex G2>", "cards":[{pubkey, section}] }`
Reconstructs `apk = Σ pubkeys` (deduped by pubkey; each must be a registered legacy
member), checks `apk ≠ O`, `asig ≠ O`, and `e(apk, H(title)) == e(G1, asig)`. If the
aggregate verifies, it tallies weight from the **attendance cards**: for each card
whose pubkey is an authorized participant, it adds `base_weight[card.section]`,
deduped by `(section, pubkey)`. If the tally ≥ threshold and `title` is the target,
it returns `{status:"approved", flag}`; otherwise `{status:"insufficient", tally, threshold}`.
An invalid aggregate returns `{status:"invalid_signature"}`.
