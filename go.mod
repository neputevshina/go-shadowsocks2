module github.com/neputevshina/go-shadowsocks2

go 1.18

replace github.com/neputevshina/go-shadowsocks2/shadowsocks => ./shadowsocks

require (
	github.com/neputevshina/go-shadowsocks2/shadowsocks v0.0.0-00010101000000-000000000000
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
)

require golang.org/x/sys v0.0.0-20191026070338-33540a1f6037 // indirect
