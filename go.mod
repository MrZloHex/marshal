module marshal

go 1.25.5

// monolink/marshal is not in v0.2.1; it arrives in v0.2.2. Until that is
// tagged, build with GOWORK=$HOME/Projects/monolith/monolink.work, then
// go get github.com/MrZloHex/monolink@v0.2.2. The workspace cannot stand in
// for a version that does not exist yet.
require (
	github.com/MrZloHex/monolink v0.2.1
	github.com/gorilla/websocket v1.5.3
	github.com/joho/godotenv v1.5.1
	github.com/lmittmann/tint v1.1.3
	github.com/spf13/pflag v1.0.10
)

require (
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
)
