# PyMix
A mix chain implementation in Python, using UDP

## What are Mixes?

A mix server commonly accumulates `n` messages, reorders them and then sends them all out at the same time. 
Thus scrambling the relationship between incoming and outgoing messages to outside observers.

    for n = 5
    
    A---\                                     /---D
    B----\             |       |             /----B
    C-------A-B-C-D-E--|  Mix  |--D-B-A-C-E-------A
    D----/             |       |             \----C
    E---/                                     \---E
    
Since an outside observer can still relate the packages based on their appearance, the mix additionally de-/encrypts the packets, before sending them out.
    
    for n = 5
    
    Enc(A)---\                                                              /---D
    Enc(B)----\                                      |       |             /----B
    Enc(C)-------Enc(A)-Enc(B)-Enc(C)-Enc(D)-Enc(E)--|  Mix  |--D-B-A-C-E-------A
    Enc(D)----/                                      |       |             \----C
    Enc(E)---/                                                              \---E
    
For this to work the client sending the packages to the mix server needs to have shared a symmetric key with it, or know a public asymmetric key of the mix, with which to encrypt the packets beforehand. For performance reasons the public key of a mix is often used to encrypt and exchange symmetric keys before the actual transmission is started. This is called hybrid encryption.

To make tracing harder and so that we do not have a single point of (anonymity) failure, two or more mixes are connected with each other in a mix chain, preferably by different mix providers. The information above, about exchanging keys, still applies in this case. The packets to be sent over the chain need to be encrypted with the respective mix keys in reverse order, so that the first mix can undo the last encryption of the packet etc: for n = 3, Enc<sub>Mix1</sub>( Enc<sub>Mix2</sub>( Enc<sub>Mix3</sub>( Request ) ) )

If 2-way communication is supported by the mix chain, responses are delivered to the mix again, decrypted/encrypted with its private key and delivered through the mix chain to the original client. Note, that encryption and decryption is the same when using symmetric keys.  
The response will arrive encrypted as many times are there are mixes in the chain. For n = 3, Enc<sub>Mix1</sub>( Enc<sub>Mix2</sub>( Enc<sub>Mix3</sub>( Response ) ) ).  
Since the client knows all the symmetric keys or the public keys of the mixes, it can decrypt the response one by one in reverse order and retrieve the plain response data.

## Why UDP?

The lack of connectivity of UDP presents some challenges not present, when working with TCP. Since UDP is useful for VoIP or streaming applications it seems interesting to see if the necessary transmission qualities can still be achieved, when anonymity is needed.

## Why Python?

This project is first and foremost an academic learning example. I'm using it to get a feel for what protocol specifications are necessary to make anonymous UDP communication over mix chains possible in the first place, which challenges are hidden in the details and how to cleanly write an implementation, that does not hide the elementary principles behind code clutter.

Performance of the language is not a major concern as long as it does not hinder the comparison of performance of different protocol approaches.
