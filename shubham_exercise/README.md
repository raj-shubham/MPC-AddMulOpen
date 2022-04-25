# MPC Implementation Exercise

## Protocol Description

There are n players `p_1, ..., p_n`. The Shamir threshold is `k` and probably
set to something like `n/3` All players are assumed to behave honestly for
simplicity.

Data to generate outside of the algorithm to be given to each player for
simplicity: random verifiable shares of 0 `z_1, ..., z_n` and corresponding
commitment `C_z`.

1. Each player `p_i` generates two random numbers `r_i` and `s_i` and creates
   verifiable sharings `r_i_1, ..., r_i_n` and `s_i_1, ..., s_i_n` for each,
   along with corresponding commitments `C_r_i` and `C_s_i`. The shares are sent to
   the corresponding parties along with the commitments.
2. Upon receiving `n` shares of the two random numbers (i.e. once `p_i` has
   received the shares and commitments from all other parties), party `p_i`
   adds all of shares for the first random number `r_i = r_1_i + ... + r_n_i` and
   commitments `C_r = C_r_1 + ... + C_r_n` and similarly computes `s_i` and `C_s`.
3. The parties then participate in the multiply and open protocol, using as
   inputs the sharings of `r` and `s` and the random sharing of 0 generated
   before running the algorithm.
4. Once multiply and open has completed, the parties have now computed `rs`.
   This is the final output of the algorithm.

## Code Structure

At the top level there is a main.go file that runs the whole program and checks
to see if it is successful. This file should not be edited. There is one
subfolder, machine, that is a go package (also called `machine`). This package is
what needs to be edited in order for the main program to execute correctly -
the task is to implement the logic that will complete the protocol described
above.

### Package `machine`

Currently this package has two types that must exist: `Machine` and `Message`.
The former represents an individual player in the protocol and the latter is
the data structure for messages that are to be sent between players during the
protocol.

The `Machine` type already has two methods: `Start` and `Handle`, and there is
a function `NewMachine` that is used to create a new instance of a `Machine`.
These functions must exist (don't delete them) for the main program to work.
Also, don't change their function signatures (i.e. don't change the fact that
`Handle` takes a `Message` and returns `([]Message, secp256k1.Fn, bool)`, and
likewise for `NewMachine` and `Start`). These functions currently don't have
implementations, so you must write them yourself. The purpose of each function
is:

1. `NewMachine`: Given the input arguments, construct a machine that will be
   used during the main program. This is just a basic contruction function.
2. `Start`: This method should return the first messages that a machine wants
   to send at the start of the protocol. So for this protocol these messages
   would be the shares of `r_i` and `s_i`.
3. `Handle`: This method is called each time the machine receives a message
   from another machine. It should perform any logic required for the protocol
   and then return: any messages it wants to now send to other parties, an
   output value and a done value. The output value should be equal to the final
   output of the protocol for that machine if and only if the returned done
   value is true. If the returned done value is false, then the output value
   will be ignored.

The `Message` type should not be changed. It has fields for which index the
message is coming from and which one it is going to. There is also a `Ty` field
which will indicate what type of message is represented by the `Data` bytes.
The `Data` bytes should be the encoding of whatever message is being sent. To
encode structures to bytes, I recommend using our `surge` library. For example,
if you have a message type

```go
type MyMessage struct {
	Field1 shamir.VerifiableShare
}
```

then you can serialise it into bytes like so:

```go
myMsg := MyMessage{Field1: value}

msgBytes, err := surge.ToBinary(myMsg)
if err != nil {
	panic(err)
}

msg := Message {
	To:   to,
	From: from,
	Ty:   myType,
	Data: msgBytes,
}
```

And deserialising can be done as follows:

```go
switch msg.Ty {
case myType:
	var myMsg MyMessage

	err := surge.FromBinary(&myMsg, msg.Data)
	if err != nil {
		panic(err)
	}

	// Use myMsg

case otherType:
	...
}
```

Note that for this to work all of the fields of the message type (`MyMessage`
in the above example) need to be public, i.e. they need to begin with a capital
letter; if the struct was

```go
type MyMessage struct {
	field1 shamir.VerifiableShare // Unexported!
}
```

then it would not work. Of course it is not necessary to use the surge library,
you can feel free to manually write your own serialisation routines.
