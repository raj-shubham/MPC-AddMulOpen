package machine

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/mpc/mulopen/mulzkp"
)

type MsgType = uint8

const (
	share = iota
	mul
	open
	max
)

type Message struct {
	To, From secp256k1.Fn

	Ty   MsgType
	Data []byte
}

type Sharing struct{
	Vshare 		shamir.VerifiableShare	
	Commitment 	shamir.Commitment
}

type RSsharing struct{
	Rsharing	Sharing
	Ssharing	Sharing
}

type ProductMessage struct{
	VShare     shamir.VerifiableShare
	Commitment secp256k1.Point
	Proof      mulzkp.Proof
	Acommit    secp256k1.Point
	Bcommit    secp256k1.Point
	H 		   secp256k1.Point
}
