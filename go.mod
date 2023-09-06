module github.com/StanfordSNR/guardian-agent

go 1.20

replace golang.org/x/crypto => github.com/StanfordSNR/crypto v0.0.0-20180224013306-e451cabda2ac

require (
	github.com/hashicorp/yamux v0.1.1
	github.com/howeyc/gopass v0.0.0-20210920133722-c8aef6fb66ef
	github.com/jessevdk/go-flags v1.5.0
	github.com/sternhenri/interact v0.0.0-20170607043113-dfeb9ef20304
	golang.org/x/crypto v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.12.0
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
)
