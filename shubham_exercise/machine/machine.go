package machine

import (
	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/mpc/mulopen/mulzkp"
	"github.com/renproject/surge"
)

type Machine struct{
	state			uint8
	k 				int
	h 				secp256k1.Point
	r				secp256k1.Fn
	s				secp256k1.Fn
	tau				secp256k1.Fn
	rShares			[]shamir.VerifiableShare
	rSharesSum 		shamir.VerifiableShare
	rSumShares		shamir.VerifiableShares
	sShares			[]shamir.VerifiableShare
	sSharesSum 		shamir.VerifiableShare
	sSumShares		shamir.VerifiableShares
	rCommitment 	[]shamir.Commitment
	rSumCommitment 	shamir.Commitment
	sCommitment 	[]shamir.Commitment
	sSumCommitment 	shamir.Commitment
	index			secp256k1.Fn
	indices			[]secp256k1.Fn
	zeroShare 		shamir.VerifiableShare
	zerocommits		shamir.Commitment
	output 			shamir.VerifiableShare
	outputShares	shamir.VerifiableShares
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
	op := shamir.NewVerifiableShare(shamir.NewShare(secp256k1.RandomFn(), secp256k1.NewFnFromU16(0)),secp256k1.RandomFn())
	machine := Machine{state:0, k:k, h:h, r: r, s: s, index:index, indices:indices, zeroShare: rzgShare, zerocommits: rzgCommitment, output:op, tau:secp256k1.RandomFn()}
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
	
	for i,index := range m.indices{
		rSharing  := Sharing{Vshare:rShares[i], Commitment:rCommitment}
		sSharing  := Sharing{Vshare:sShares[i], Commitment:sCommitment}
		r_s_Sharing := RSsharing{Rsharing:rSharing, Ssharing:sSharing}
		r_s_MarshalledSharing, _ := surge.ToBinary(&r_s_Sharing)
		msg = append(msg, Message{To:index, From:m.index, Ty:share, Data:r_s_MarshalledSharing})
	}
	
	return msg
}

func (m *Machine) Handle(msg Message) ([]Message, secp256k1.Fn, bool) {
	var msgbuffer []Message 
	var output secp256k1.Fn
	var flag bool
	flag = false
	output = secp256k1.RandomFn()
	switch msg.Ty {
	case share:
		var MarshalledSharing RSsharing
		var product secp256k1.Fn
		surge.FromBinary(&MarshalledSharing, msg.Data)
		rshare := MarshalledSharing.Rsharing
		sshare := MarshalledSharing.Ssharing
		if ((!shamir.IsValid(m.h, &rshare.Commitment, &rshare.Vshare))&&
			(!shamir.IsValid(m.h, &sshare.Commitment, &sshare.Vshare))){
				panic("Invalid shares")
			}
		m.rShares = append(m.rShares, rshare.Vshare)
		m.rCommitment = append(m.rCommitment, rshare.Commitment)
		m.sShares = append(m.sShares, sshare.Vshare)
		m.sCommitment = append(m.sCommitment, sshare.Commitment)
		if len(m.indices) == len(m.rShares){
			rsum := m.rShares[0]
			rtempCommitment := m.rCommitment[0]
			ssum := m.sShares[0]
			stempCommitment := m.sCommitment[0]

			for i,share := range m.rShares{
				if 0 != i {
					rsum.Add(&rsum, &share)
				}
			}
			for i,share := range m.sShares{
				if 0 != i {
					ssum.Add(&ssum, &share)
				}
			}
			
			for i,com := range m.rCommitment{
				if 0 != i {
					rtempCommitment.Add(rtempCommitment, com)
				}
			}
			for i,com := range m.sCommitment{
				if 0 != i {
					stempCommitment.Add(stempCommitment, com)
				}
			}
			m.rSharesSum = rsum
			m.sSharesSum = ssum
			m.rSumCommitment = rtempCommitment
			m.sSumCommitment = stempCommitment
			product.Mul(&m.rSharesSum.Share.Value, &m.sSharesSum.Share.Value)
			aShareCommitment := PolyEvalPoint(m.rSumCommitment, m.index)
			bShareCommitment := PolyEvalPoint(m.sSumCommitment, m.index)
			productShareCommitment := pedersenCommit(&product, &m.tau, &m.h)
			share := shamir.VerifiableShare{
				Share: shamir.Share{
					Index: m.index,
					Value: product,
				},
				Decommitment: m.tau,
			}
			proof := mulzkp.CreateProof(&m.h, &aShareCommitment, &bShareCommitment, &productShareCommitment,
				m.rSharesSum.Share.Value, m.sSharesSum.Share.Value,
				m.rSharesSum.Decommitment, m.sSharesSum.Decommitment, m.tau,
			)
			share.Add(&share, &m.zeroShare)
			msgProd := ProductMessage{VShare:share, Commitment:productShareCommitment, Proof:proof,
						Acommit:aShareCommitment, Bcommit:bShareCommitment}
			Marshalled, _ := surge.ToBinary(&msgProd)
			m.state += 1
			for _,ind := range m.indices{
				msgbuffer = append(msgbuffer, Message{To:ind, From:m.index, Ty:open, Data:Marshalled})	
			}
		}
	case open:
		var unMarshalled ProductMessage
		surge.FromBinary(&unMarshalled, msg.Data)
		zkpVerify := mulzkp.Verify(&m.h, &unMarshalled.Acommit, &unMarshalled.Bcommit, &unMarshalled.Commitment, &unMarshalled.Proof)
		if !zkpVerify{
			panic("Product verification failed")
		}
		m.outputShares = append(m.outputShares, unMarshalled.VShare)
		if len(m.outputShares) == len(m.indices){
			output = shamir.Open(m.outputShares.Shares())
			flag = true
		}

	default:
		/* code */
	}
	return msgbuffer, output, flag
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