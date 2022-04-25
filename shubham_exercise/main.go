package main

import (
	"fmt"
	"local/shubhamexample/machine"
	"math/rand"

	"github.com/renproject/secp256k1"
	"github.com/renproject/shamir"
	"github.com/renproject/shamir/shamirutil"
)

func main() {
	n := 10
	k := 5
	h := secp256k1.RandomPoint()

	indices := shamirutil.SequentialIndices(n)

	rzgShares := make(shamir.VerifiableShares, len(indices))
	rzgCommitment := shamir.NewCommitmentWithCapacity(2*k - 1)
	shamir.VShareSecret(&rzgShares, &rzgCommitment, indices, h, secp256k1.NewFnFromU16(0), 2*k-1)

	machines := make(map[secp256k1.Fn]*machine.Machine, n)
	rs := make([]secp256k1.Fn, n)
	ss := make([]secp256k1.Fn, n)
	for i, index := range indices {
		var m machine.Machine
		m, rs[i], ss[i] = machine.NewMachine(index, indices, k, h, rzgShares[i], rzgCommitment)
		machines[index] = &m
	}

	r := fnSum(rs)
	s := fnSum(ss)

	var expectedOutput secp256k1.Fn
	expectedOutput.Mul(&r, &s)

	outputs := runMachines(machines)
	
	if len(outputs) != n {
		fmt.Printf("not all machines produced an output: only %v/%v outputs returned\n", len(outputs), n)
		return
	}

	success := true
	for i, output := range outputs {
		if !output.Eq(&expectedOutput) {
			fmt.Printf("bad output for machine with index %v!\n", i.Int())
			success = false
		}
	}

	if success {
		fmt.Println("protocol completed successfully!")
	} else {
		fmt.Println("protocol failed!")
	}
}

func fnSum(fns []secp256k1.Fn) secp256k1.Fn {
	sum := secp256k1.NewFnFromU16(0)
	for _, fn := range fns {
		sum.Add(&sum, &fn)
	}
	return sum
}

func runMachines(machines map[secp256k1.Fn]*machine.Machine) map[secp256k1.Fn]secp256k1.Fn {
	msgBuffer := make([]machine.Message, 0, 128)

	for _, machine := range machines {
		msgs := machine.Start()
		msgBuffer = append(msgBuffer, msgs...)
	}

	outputs := make(map[secp256k1.Fn]secp256k1.Fn, len(machines))

	for len(msgBuffer) > 0 {
		msg := msgBuffer[0]

		index := msg.To

		newMsgs, output, done := machines[index].Handle(msg)

		if len(msgBuffer) == 1 {
			msgBuffer = msgBuffer[:0]
		} else {
			msgBuffer[0] = msgBuffer[len(msgBuffer)-1]
			msgBuffer = msgBuffer[:len(msgBuffer)-1]
		}
		msgBuffer = append(msgBuffer, newMsgs...)
		rand.Shuffle(len(msgBuffer), func(i, j int) { msgBuffer[i], msgBuffer[j] = msgBuffer[j], msgBuffer[i] })

		if done {
			outputs[index] = output
		}
	}

	return outputs
}
