module shdns

go 1.23.0

require (
	github.com/google/nftables v0.3.0
	github.com/mdlayher/netlink v1.8.0
	golang.org/x/sys v0.35.0
)

replace github.com/google/nftables => ./nftables

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
)
