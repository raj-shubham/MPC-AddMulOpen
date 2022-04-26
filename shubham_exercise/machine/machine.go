package machine

import (
	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/surge"
)

type Machine struct {
	k            int
	h            secp256k1.Point
	r            secp256k1.Fn
	s            secp256k1.Fn
	rShares      []shamir.VerifiableShare
	sShares      []shamir.VerifiableShare
	rCommitment  []shamir.Commitment
	sCommitment  []shamir.Commitment
	index        secp256k1.Fn
	indices      []secp256k1.Fn
	zeroShare    shamir.VerifiableShare
	zeroCommits  shamir.Commitment
	outputShares shamir.VerifiableShares
}

func NewMachine(
	index secp256k1.Fn,
	indices []secp256k1.Fn,
	k int,
	h secp256k1.Point,
	rzgShare shamir.VerifiableShare,
	rzgCommitment shamir.Commitment,
) (Machine, secp256k1.Fn, secp256k1.Fn) {
	r := secp256k1.RandomFn()
	s := secp256k1.RandomFn()
	machine := Machine{k: k, h: h, r: r, s: s, index: index, indices: indices, zeroShare: rzgShare, zeroCommits: rzgCommitment}
	return machine, r, s
}

func (m *Machine) Start() []Message {
	var msg []Message
	rShares := make(shamir.VerifiableShares, len(m.indices))
	rCommitment := shamir.NewCommitmentWithCapacity(m.k)
	shamir.VShareSecret(&rShares, &rCommitment, m.indices, m.h, m.r, m.k)
	sShares := make(shamir.VerifiableShares, len(m.indices))
	sCommitment := shamir.NewCommitmentWithCapacity(m.k)
	shamir.VShareSecret(&sShares, &sCommitment, m.indices, m.h, m.s, m.k)

	for i, index := range m.indices {
		rSharing := Sharing{Vshare: rShares[i], Commitment: rCommitment}
		sSharing := Sharing{Vshare: sShares[i], Commitment: sCommitment}
		rsSharing := RSsharing{Rsharing: rSharing, Ssharing: sSharing}
		rsMarshalledSharing, _ := surge.ToBinary(&rsSharing)
		msg = append(msg, Message{To: index, From: m.index, Ty: share, Data: rsMarshalledSharing})
	}

	return msg
}

func (m *Machine) Handle(msg Message) ([]Message, secp256k1.Fn, bool) {
	var msgBuffer []Message
	var output secp256k1.Fn
	var done bool
	done = false
	output = secp256k1.RandomFn()
	switch msg.Ty {
	case share:
		var marshalledSharing RSsharing
		var product secp256k1.Fn
		surge.FromBinary(&marshalledSharing, msg.Data)
		rShare := marshalledSharing.Rsharing
		sShare := marshalledSharing.Ssharing
		if (!shamir.IsValid(m.h, &rShare.Commitment, &rShare.Vshare)) &&
			(!shamir.IsValid(m.h, &sShare.Commitment, &sShare.Vshare)) {
			panic("Invalid shares")
		}
		m.rShares = append(m.rShares, rShare.Vshare)
		m.rCommitment = append(m.rCommitment, rShare.Commitment)
		m.sShares = append(m.sShares, sShare.Vshare)
		m.sCommitment = append(m.sCommitment, sShare.Commitment)
		if len(m.indices) == len(m.rShares) {
			rSum := vshareSum(m.rShares)
			sSum := vshareSum(m.sShares)
			rTempCommitment := commitSum(m.rCommitment)
			sTempCommitment := commitSum(m.sCommitment)
			tau := secp256k1.RandomFn()
			product.Mul(&rSum.Share.Value, &sSum.Share.Value)
			aShareCommitment := PolyEvalPoint(rTempCommitment, m.index)
			bShareCommitment := PolyEvalPoint(sTempCommitment, m.index)
			productShareCommitment := pedersenCommit(&product, &tau, &m.h)
			share := shamir.VerifiableShare{
				Share: shamir.Share{
					Index: m.index,
					Value: product,
				},
				Decommitment: tau,
			}
			proof := mulzkp.CreateProof(&m.h, &aShareCommitment, &bShareCommitment, &productShareCommitment,
				rSum.Share.Value, sSum.Share.Value,
				rSum.Decommitment, sSum.Decommitment, tau,
			)
			share.Add(&share, &m.zeroShare)
			msgProd := ProductMessage{VShare: share, Commitment: productShareCommitment, Proof: proof,
				Acommit: aShareCommitment, Bcommit: bShareCommitment}
			marshalled, _ := surge.ToBinary(&msgProd)
			for _, ind := range m.indices {
				msgBuffer = append(msgBuffer, Message{To: ind, From: m.index, Ty: open, Data: marshalled})
			}
		}
	case open:
		var unmarshalled ProductMessage
		surge.FromBinary(&unmarshalled, msg.Data)
		zkpVerify := mulzkp.Verify(&m.h, &unmarshalled.Acommit, &unmarshalled.Bcommit, &unmarshalled.Commitment, &unmarshalled.Proof)
		if !zkpVerify {
			panic("Product verification failed")
		}
		m.outputShares = append(m.outputShares, unmarshalled.VShare)
		if len(m.outputShares) == len(m.indices) {
			output = shamir.Open(m.outputShares.Shares())
			done = true
		}

	default:
		/* code */
	}
	return msgBuffer, output, done
}

func pedersenCommit(value, decommitment *secp256k1.Fn, h *secp256k1.Point) secp256k1.Point {
	var commitment, hPow secp256k1.Point
	commitment.BaseExp(value)
	hPow.Scale(h, decommitment)
	commitment.Add(&commitment, &hPow)
	return commitment
}

func PolyEvalPoint(commitment shamir.Commitment, index secp256k1.Fn) secp256k1.Point {
	var acc secp256k1.Point
	acc = commitment[len(commitment)-1]
	for l := len(commitment) - 2; l >= 0; l-- {
		acc.Scale(&acc, &index)
		acc.Add(&acc, &commitment[l])
	}
	return acc
}

func vshareSum(vshare shamir.VerifiableShares) shamir.VerifiableShare {
	sum := vshare[0]
	for i, share := range vshare {
		if 0 != i {
			sum.Add(&sum, &share)
		}
	}
	return sum
}

func commitSum(commit []shamir.Commitment) shamir.Commitment {
	sum := commit[0]
	for i, share := range commit {
		if 0 != i {
			sum.Add(sum, share)
		}
	}
	return sum
}
