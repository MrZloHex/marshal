
  ░▒▓█ _marshal_ █▓▒░
  The people of the bubble: who they are, which panel each is signed in
  at, and what they may do. SPEC.txt §24.


  ───────────────────────────────────────────────────────────────
  ▓ WHAT IT IS

  A class-1 node at MARSHAL, speaking monolink v2 only. It checks who a
  person is, and signs the tickets by which the hub holds each panel to
  that person's grants (SECURITY.txt §5): a panel with no ticket can speak
  to marshal and nobody else.

  Its own records it guards itself. A request to change people must come
  from <panel>.<person>, that panel must hold a live session for that
  person, and their grants must cover MARSHAL.<VERB>.<NOUN>.


  ───────────────────────────────────────────────────────────────
  ▓ SIGNING IN

  There are no secrets. A person signs in with a key that never leaves
  their device, and marshal keeps only its public half (SECURITY.txt §6):

  ▪ a passkey — on a phone, a laptop or a hardware key, used through the
    app. The fingerprint, face or PIN stays on the device; what reaches
    marshal is a signature over its challenge and the site's origin.
  ▪ a panel's own key — Ed25519, held by monoview in a file locked with a
    passphrase, until a hardware key takes its place.

    panel ── AUTH:CHALLENGE ─────────────────────────────▶ marshal
    panel ◀── OK:CHALLENGE:<nonce> ───────────────────────
    panel ── AUTH:PASSKEY:<nonce>:<credential>:<authdata>:<signature>:<clientdata>…
    panel ── AUTH:KEY:<nonce>:<name>:<credential>:<signature>   (a panel's key)
    panel ◀── OK:SESSION:<token>:<name>:<expires> ─────────

  ▪ A nonce is 32 random bytes, base64url; it answers once, within a
    minute, and only for the panel that asked for it.
  ▪ A passkey must come from --origin, be made for --rp-id, and have
    verified the person; a counter that goes back is a copied key, refused.
    The client data may take several fields: browsers add to it.
  ▪ A panel's key signs "monolith-key\0<name>\0<panel>\0<nonce>".
  ▪ Nothing is locked out for a wrong signature: a signature cannot be
    guessed. Codes can, and are (below).
  ▪ A session belongs to the panel that opened it, and to the key that
    opened it. It lasts an hour unused; SET:SESSION and every GET:TICKET
    extend it, so a panel still connected keeps it, and one gone lets it
    lapse.

  The panel side is `github.com/MrZloHex/monolink/marshal`: Challenge,
  SignInPasskey, SignInKey, Enrol, Redeem, Resume, SignOut, and the calls
  below. Use it rather than reimplementing the checks.


  ───────────────────────────────────────────────────────────────
  ▓ THE FIRST PERSON, AND EVERYONE AFTER

  While nobody can sign in, marshal mints an enrolment code — twelve
  characters, XXXX-XXXX-XXXX — and prints it on UKAZ. If nothing answers,
  the code goes to the log instead:

    journalctl -u marshal | grep 'ENROLMENT CODE'

  Entered at monoview with a name, it keeps monoview's key as that
  person's, grants them "*", signs them in, and is void. portal refuses it
  from the internet. Restarting marshal while nobody can sign in mints a
  new one. A marshal.json from before keys counts as nobody: its people
  keep their grants, lose their secrets, and are invited back.

  Everyone else comes in by invitation: NEW:INVITE:<name> gives a
  one-time code, good for an hour, which the person enters in the app with
  their name; their phone makes a passkey, and it is theirs.

  ▪ Anyone may invite themselves: a new device.
  ▪ Someone new needs MARSHAL.NEW.INVITE, and starts with no grants.
  ▪ Someone else who exists needs MARSHAL.SET.KEY, and every grant they
    hold: whoever has a key of theirs can become them. It is how a person
    who lost every device gets back.
  ▪ Every invitation needs a sign-in within the last five minutes: a new
    key must not come of a session someone left open, or took.
  ▪ An invitation is judged again when taken up. One for someone new adds
    no key to whoever has the name by then; one whose maker has lost the
    grant for it, been removed, or had a key removed since, is void — a
    stolen key's self-invitation dies with the key.
  ▪ A newer invitation for the same name from the same person replaces
    the older. A person has three out at most, the bubble sixteen.
  ▪ A removed person's name is never given again: other nodes know people
    by name, and someone new must not inherit what was theirs.

  A code is 60 random bits: at the hub's hundred frames a second, guessing
  one takes some three hundred million years, so a right code is never
  refused for wrong ones before it. Past five wrong codes from one panel
  for one name (for the enrolment code, from one panel), more are answered
  BUSY for 30 s, doubling to 15 min, and the log names them; the count is
  forgotten after an hour's quiet. A panel has at most 64 challenges out
  at once.


  ───────────────────────────────────────────────────────────────
  ▓ COMMANDS

    AUTH:CHALLENGE                            -> OK:CHALLENGE:<nonce>
    AUTH:PASSKEY:<nonce>:<id>:<ad>:<sig>:<cd>… -> OK:SESSION:<token>:<name>:<expires>
    AUTH:KEY:<nonce>:<name>:<id>:<sig>        -> OK:SESSION:…
    AUTH:ENROL:<code>:<name>:<credential>     -> OK:SESSION:…
    AUTH:REDEEM:<code>:<name>:<credential>    -> OK:SESSION:…
    SET:SESSION:<token>                       -> OK:SESSION:<token>:<name>:<expires>
    STOP:SESSION:<token>                      -> OK:SESSION:<token>:<name>:<now>
    GET:ALLOW:<token>:<action>                -> OK:ALLOW:YES | OK:ALLOW:NO:<reason>
    GET:TICKET:<token>                        -> OK:TICKET:<person>:<panel>:<expires>:<sig>[:<grant>...]

  A credential is <kind>:<id>:<alg>:<key>[:<label>] — webauthn or ed25519,
  the credential id (base64url), the COSE algorithm (-7 ES256, -8 EdDSA),
  the public key as SubjectPublicKeyInfo DER (base64url), and what the
  person calls it: at most 48 bytes, no ":", "|" or "%".

  Administration — each is the action MARSHAL.<VERB>.<NOUN>:

    GET:SESSIONS                              -> OK:SESSIONS[:<user>|<panel>|<since>...]  the newest sixteen
    STOP:SESSIONS:<name>                      -> OK:SESSIONS:<name>:<ended>  yourself: no grant needed
    GET:USERS                                 -> OK:USERS[:<name>...]
    NEW:INVITE:<name>                         -> OK:INVITE:<code>:<expires>   see above
    GET:KEYS:<name>                           -> OK:KEYS[:<ref>|<kind>|<label>|<added>...]  yourself: no grant needed
    STOP:KEY:<name>:<ref>                     -> OK:KEY:<name>:<ref>  yourself: no grant needed
    STOP:USER:<name>                          -> OK:USER:<name>
    SET:GRANT:<user>:<pattern>                -> OK:GRANT:<user>
    STOP:GRANT:<user>:<pattern>               -> OK:GRANT:<user>
    GET:GRANTS:<user>                         -> OK:GRANTS[:<pattern>...]  yourself: no grant needed

  A key's <ref> is the first 8 bytes of the SHA-256 of its credential id,
  hex. Removing a key ends the sessions it opened; the last key stays.

  A grant is an action, or a prefix ending in ".*": VERTEX.*,
  UKAZ.DO.PRINT.*, GOVERNOR.GET.*, or "*" for everything. The star follows
  a dot, so it covers whole parts of a name. Nothing is permitted that no
  grant names. A person grants and revokes only what their own grants
  cover, and changes nobody who may do more than they may: SET.GRANT is
  not a way to become "*". The last person holding "*" who can sign in can
  be neither removed nor stripped of it. A person holds at most eleven
  grants: a ticket carries them all, in one frame.

  A session lasts an hour unused, renewed by every ticket, and thirty days
  at most however it is renewed. A person has at most sixteen open; one
  more ends the oldest. Signing out, and a session ended for room, end the
  person's tickets at the hub — it cannot tell one session's from
  another's — and their other panels simply ask for new ones.

  STOP:SESSIONS:<name> signs a person out everywhere: every session,
  invitation and ticket of theirs, for when a device is gone and its token
  with it. Their keys stay; STOP:KEY removes one known lost.

  A ticket is what a panel shows the hub to act for its person: signed with
  marshal's Ed25519 key, for the session's own panel, for ten minutes or
  less (SECURITY.txt §5). When a person's grants or keys change, they sign
  out, or they are removed, marshal has the hub end their tickets at once
  (CONCENTRATOR:STOP:TICKETS). The cutoff is saved with the change, and
  sent again after a reconnect or a restart until the hub acknowledges it
  or every ticket it covers has expired; TICKETS.ENDING counts the people
  still waiting.

  Errors: DENIED (a key, signature, challenge or code not accepted, a
  missing grant, not signed in), BUSY:<s> (codes locked out), NAC (no such
  session, person, key or grant), STATE (exists already, enrolment
  closed, last "*", last key), ARG, ARGC.

  Properties: USERS.COUNT, SESSIONS.COUNT, ENROLLING, TICKETS.ENDING,
  UPTIME, VERSION, and PEOPLE — the names alone, a record (dasha|mzh),
  readable by any node and published on change, so synapse knows whom a
  message can go to. A bubble holds as many people as that one field and
  one GET:USERS frame can name: sixteen, fewer with long names.


  ───────────────────────────────────────────────────────────────
  ▓ STATE

  One file, marshal.json, mode 0600, rewritten atomically on each change.
  It holds people with their public keys and grants, and sessions keyed by
  the SHA-256 of their token. Nothing in it signs anybody in: reading it
  tells you who is signed in where, and gives you no session.


  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN

    go build -o bin/marshal ./cmd/marshal
    go test ./...


  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION

  Flags, with .env in the working directory supplying defaults:

    -u, --url           MARSHAL_HUB_URL       wss://127.0.0.1:8443
    -s, --state         MARSHAL_STATE         marshal.json
        --session-ttl   MARSHAL_SESSION_TTL   1h
        --rp-id         MARSHAL_RP_ID         monolith-system.net
        --origin        MARSHAL_ORIGIN        https://monolith-system.net  (comma-separated)
        --printer       MARSHAL_PRINTER       UKAZ   (empty: log the code)
        --ticket-key    MARSHAL_TICKET_KEY    ticket.key
        --tls-cert      MARSHAL_TLS_CERT
        --tls-key       MARSHAL_TLS_KEY
        --tls-ca        MARSHAL_TLS_CA        the bubble CA
    -l, --log           MARSHAL_LOG           info

  It does not start without all three TLS files and a wss:// URL: it
  trusts whoever the hub says sent a frame, so anything else at the hub's
  port could speak as anyone, and read the enrolment code on its way to
  the printer. An empty --origin is refused too.


  The ticket key, and its public half for the hub:

    openssl genpkey -algorithm ed25519 -out ticket.key && chmod 600 ticket.key
    openssl pkey -in ticket.key -pubout -out ticket.pub

  ───────────────────────────────────────────────────────────────
  ▓ DEPLOY

  Through deploy/'s monolithctl, with MONOLITH's release: its own user, a
  sandboxed unit, its TLS and ticket keys sealed by the TPM
  (deploy/README.txt). Whoever can replace marshal's binary, state or
  ticket key owns the bubble's sign-in; that is why none of them may sit
  in anyone's home directory.

