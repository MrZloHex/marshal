
  ░▒▓█ _marshal_ █▓▒░
  The people of the bubble: who they are, which panel each is signed in
  at, and what they may do. SPEC.txt §24.


  ───────────────────────────────────────────────────────────────
  ▓ WHAT IT IS

  A class-1 node at MARSHAL, speaking monolink v2 only. Panels ask it
  whether a person may do something; it answers; the panel honours the
  answer. It is policy, not a security boundary — anyone holding a bubble
  certificate can write frames directly, and in this bubble that is the
  same act as owning the place.

  What marshal does guard is its own records. A request to change people
  must come from <panel>.<person>, that panel must hold a live session for
  that person, and their grants must cover MARSHAL.<VERB>.<NOUN>.


  ───────────────────────────────────────────────────────────────
  ▓ SIGNING IN

  A secret never crosses the bus. The concentrator relays every frame to
  every client, so the panel proves it knows the secret instead:

    panel ── AUTH:USER:<name> ───────────────────────▶ marshal
    panel ◀── OK:CHALLENGE:<kdf>:<nonce> ──────────────
    panel ── AUTH:PROOF:<name>:<nonce>:<proof> ───────▶
    panel ◀── OK:SESSION:<token>:<name>:<expires> ─────

  <kdf> says how to turn the secret into a verifier: argon2id, with the
  cost and salt chosen when the secret was set. <proof> is HMAC-SHA256
  keyed with the verifier, over the name, the panel and the nonce. marshal
  keeps the verifier, never the secret.

  ▪ A nonce answers once, within a minute.
  ▪ A name nobody has still gets a challenge — the same one each time.
  ▪ Five wrong answers lock a name out for 30 s, doubling to 15 min.
  ▪ A session belongs to the panel that opened it. It lasts 30 days
    unused; SET:SESSION extends it.

  The panel side is `github.com/MrZloHex/monolink/marshal`: SignIn, Enrol,
  Resume, SignOut, and the calls below. Use it rather than reimplementing
  the proof.


  ───────────────────────────────────────────────────────────────
  ▓ THE FIRST PERSON

  With nobody in the bubble, marshal mints an enrolment code — twelve
  characters, XXXX-XXXX-XXXX — and prints it on UKAZ. If nothing answers,
  the code goes to the log instead:

    journalctl -u marshal | grep 'ENROLMENT CODE'

  Entered at a panel with a name and a secret, it creates the first
  person, grants them "*", signs them in, and is void. Restarting marshal
  while nobody exists mints a new one.


  ───────────────────────────────────────────────────────────────
  ▓ COMMANDS

    AUTH:USER:<name>                          -> OK:CHALLENGE:<kdf>:<nonce>
    AUTH:PROOF:<name>:<nonce>:<proof>         -> OK:SESSION:<token>:<name>:<expires>
    AUTH:ENROL:<code>:<name>:<kdf>:<verifier> -> OK:SESSION:<token>:<name>:<expires>
    SET:SESSION:<token>                       -> OK:SESSION:<token>:<name>:<expires>
    STOP:SESSION:<token>                      -> OK:SESSION:<token>:<name>:<now>
    GET:ALLOW:<token>:<action>                -> OK:ALLOW:YES | OK:ALLOW:NO:<reason>

  Administration — each is the action MARSHAL.<VERB>.<NOUN>:

    GET:SESSIONS                              -> OK:SESSIONS[:<user>|<panel>|<since>...]
    GET:USERS                                 -> OK:USERS[:<name>...]
    NEW:USER:<name>:<kdf>:<verifier>          -> OK:USER:<name>
    SET:USER:<name>:<kdf>:<verifier>          -> OK:USER:<name>     yourself: no grant needed
    STOP:USER:<name>                          -> OK:USER:<name>
    SET:GRANT:<user>:<pattern>                -> OK:GRANT:<user>
    STOP:GRANT:<user>:<pattern>               -> OK:GRANT:<user>
    GET:GRANTS:<user>                         -> OK:GRANTS[:<pattern>...]  yourself: no grant needed

  A grant is an action or a prefix ending in "*": VERTEX.*,
  UKAZ.DO.PRINT.*, GOVERNOR.GET.*, or "*" for everything. Nothing is
  permitted that no grant names. The last person holding "*" can be
  neither removed nor stripped of it.

  Errors: DENIED (wrong secret, missing grant, not signed in), BUSY:<s>
  (locked out), NAC (no such session, person or grant), STATE (exists
  already, enrolment closed, last "*"), ARG, ARGC.

  Properties: USERS.COUNT, SESSIONS.COUNT, ENROLLING, UPTIME, VERSION, and
  PEOPLE — the names alone, a record (dasha|mzh), readable by any node and
  published on change, so synapse knows whom a message can go to.


  ───────────────────────────────────────────────────────────────
  ▓ STATE

  One file, marshal.json, mode 0600, rewritten atomically on each change.
  It holds people with their KDF, verifier and grants, and sessions keyed
  by the SHA-256 of their token — reading it tells you who is signed in
  where, and gives you no session.


  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN

    go build -o bin/marshal ./cmd/marshal
    go test ./...


  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION

  Flags, with .env in the working directory supplying defaults:

    -u, --url           MARSHAL_HUB_URL       ws://localhost:8092
    -s, --state         MARSHAL_STATE         marshal.json
        --session-ttl   MARSHAL_SESSION_TTL   720h
        --printer       MARSHAL_PRINTER       UKAZ   (empty: log the code)
        --tls-cert      MARSHAL_TLS_CERT
        --tls-key       MARSHAL_TLS_KEY
        --tls-ca        MARSHAL_TLS_CA
    -l, --log           MARSHAL_LOG           info

  On the server, beside achtung and governor:

    MARSHAL_HUB_URL=wss://127.0.0.1:8443
    MARSHAL_TLS_CERT=../pki/marshal/marshal.cert.pem
    MARSHAL_TLS_KEY=../pki/marshal/marshal.key.pem
    MARSHAL_TLS_CA=../pki/intermediate/certs/ca-chain.cert.pem


  ───────────────────────────────────────────────────────────────
  ▓ DEPLOY

    cd ~/Projects/monolith/pki && ./issue.sh marshal
    cd ~/Projects/monolith/marshal && go build -o bin/marshal ./cmd/marshal
    sudo cp marshal.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now marshal

