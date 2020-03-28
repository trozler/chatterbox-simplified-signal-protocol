// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

//Written by Tony Rosler (tcr278) and Bryan Jia Gu (bjg416).

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal

	"bytes"
	"encoding/binary"
	"errors"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey //Value is recieve counter.
	SendCounter       int
	LastUpdate        int //indicating which message number was the first sent with the newly updated sending chain
	ReceiveCounter    int
	LastAction        int //0 if send, 1 if recieve.
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int //indicating which message number was the first sent with the newly updated sending chain
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}
	c.Sessions[*partnerIdentity].SendChain.Zeroize()
	c.Sessions[*partnerIdentity].ReceiveChain.Zeroize()
	c.Sessions[*partnerIdentity].RootChain.Zeroize()
	c.Sessions[*partnerIdentity].MyDHRatchet.Zeroize()
	c.Sessions[*partnerIdentity].SendCounter = 0
	c.Sessions[*partnerIdentity].ReceiveCounter = 0
	c.Sessions[*partnerIdentity].LastUpdate = 0
	c.Sessions[*partnerIdentity].LastAction = 0

	for key, val := range c.Sessions[*partnerIdentity].CachedReceiveKeys {
		val.Zeroize()
		delete(c.Sessions[*partnerIdentity].CachedReceiveKeys, key)
	}

	delete(c.Sessions, *partnerIdentity)

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which initiates should be
// the first to choose a new DH ratchet value. Part of this code has been
// provided for you, you will need to fill in the key derivation code.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(), //Generating new ephemeral keys
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
}

// ReturnHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. Part of this code has been provided for you, you will
// need to fill in the key derivation code. The partner which calls this
// method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(), //Generating new ephemeral keys
		PartnerDHRatchet:  partnerEphemeral,
		LastAction:        1, //Set to 1. If Bob speaks first then will be forced to ratchet and generate new ephemeral.
	}
	c.Sessions[*partnerIdentity].RootChain = CombineKeys(DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey), DHCombine(partnerEphemeral, &c.Identity.PrivateKey), DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))
	handshakeReturn := c.Sessions[*partnerIdentity].RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)
	c.Sessions[*partnerIdentity].ReceiveChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
	c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL) //Protect by ratcheting
	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, handshakeReturn, nil //Saves return values at this points anbd executes at end of method.

}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake. Part of this code has been provided, you will
// need to fill in the key derivation code. The partner which calls this
// method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral
	c.Sessions[*partnerIdentity].RootChain = CombineKeys(DHCombine(partnerEphemeral, &c.Identity.PrivateKey), DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey), DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))
	handshakeReturn := c.Sessions[*partnerIdentity].RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)

	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain
	c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL) //Protect by ratcheting
	c.Sessions[*partnerIdentity].ReceiveChain = c.Sessions[*partnerIdentity].RootChain

	c.Sessions[*partnerIdentity].LastUpdate = 1 //If Alice send first message need LastUpdate to be 1.
	//If A doesnt send first message, then no harm done will be set to 1 anyways.

	return handshakeReturn, nil
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}
	c.Sessions[*partnerIdentity].SendCounter++
	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		IV:       NewIV(),
		Counter:  c.Sessions[*partnerIdentity].SendCounter,
	}
	//We have to ratchet root key and generte new ephemeral keys.
	if c.Sessions[*partnerIdentity].LastAction == 1 {

		//Zeroise old keys
		c.Sessions[*partnerIdentity].MyDHRatchet.Zeroize()
		oldRoot := c.Sessions[*partnerIdentity].RootChain

		//Generate new ephemeral key, ratchet root and derive chain and message keys.
		c.Sessions[*partnerIdentity].MyDHRatchet = GenerateKeyPair()
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain, DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey))
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].RootChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL) //Ratchet for next turn
		c.Sessions[*partnerIdentity].LastAction = 0
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter //First message sent on this chain.

		oldRoot.Zeroize()

	} else {
		oldChain := c.Sessions[*partnerIdentity].SendChain
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
		oldChain.Zeroize()
	}

	message.LastUpdate = c.Sessions[*partnerIdentity].LastUpdate
	message.NextDHRatchet = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey
	messageKey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)

	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), message.IV)
	messageKey.Zeroize()

	return message, nil
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	oldRecVal := c.Sessions[*message.Sender].ReceiveCounter
	c.Sessions[*message.Sender].ReceiveCounter++ //Equals id of message we expect
	var messageKey *SymmetricKey = nil

	oldRoot := c.Sessions[*message.Sender].RootChain.Duplicate()
	oldRec := c.Sessions[*message.Sender].ReceiveChain.Duplicate()
	prevAction := c.Sessions[*message.Sender].LastAction
	potentialMkeys := make(map[int]*SymmetricKey) //Need to have a temp map for when we recieve many corrupted messages in a row and then finally recieve a valid messsage and we have just switched from sending.
	oldPartnerDHRatchet := c.Sessions[*message.Sender].PartnerDHRatchet

	if message.Counter < c.Sessions[*message.Sender].ReceiveCounter { //Get messages from cache and zeroise then delete entry.
		c.Sessions[*message.Sender].ReceiveCounter-- //Accesing cached message should not increment received counter. As Rec already accounted for this.

		if messageKey, ok := c.Sessions[*message.Sender].CachedReceiveKeys[message.Counter]; ok { //Check if key in map
			decipheredText, err := messageKey.AuthenticatedDecrypt((*message).Ciphertext, message.EncodeAdditionalData(), (*message).IV)
			if err != nil {
				return "", errors.New("Cipher text has been modified - break1")
			}
			messageKey.Zeroize()
			delete(c.Sessions[*message.Sender].CachedReceiveKeys, message.Counter)
			return decipheredText, nil
		}

		return "", errors.New("Replay of previously deciphered message")

	} else if !bytes.Equal(c.Sessions[*message.Sender].PartnerDHRatchet.Fingerprint(), message.NextDHRatchet.Fingerprint()) {

		for i := c.Sessions[*message.Sender].ReceiveCounter; i < message.LastUpdate; i++ { //Catch up on old chain if necessary. How do we know still messags on old receive chian.
			potentialCachedKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
			potentialMkeys[i] = potentialCachedKey //Key is receive counter corrspond to message, val is message key.
			tempRec := c.Sessions[*message.Sender].ReceiveChain
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			tempRec.Zeroize()

			c.Sessions[*message.Sender].ReceiveCounter++
		}
		prevRoot := c.Sessions[*message.Sender].RootChain
		c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
		c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, DHCombine(c.Sessions[*message.Sender].PartnerDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey))
		tempRoot := c.Sessions[*message.Sender].RootChain
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL) //Get first recieve chain.

		for i := c.Sessions[*message.Sender].ReceiveCounter; i <= message.Counter; i++ { //Catch up on futur chain if necessary.
			potentialCachedKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
			potentialMkeys[i] = potentialCachedKey
			tempRec := c.Sessions[*message.Sender].ReceiveChain
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			tempRec.Zeroize()

			c.Sessions[*message.Sender].ReceiveCounter++
		}
		c.Sessions[*message.Sender].ReceiveCounter--

		c.Sessions[*message.Sender].RootChain = c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL) //Let root chain be pre ratchetd for security and so we can go straight into send.
		c.Sessions[*message.Sender].LastAction = 1
		tempRoot.Zeroize()
		prevRoot.Zeroize()

	} else { //Only have to bring Recieve chain up to date.
		for i := c.Sessions[*message.Sender].ReceiveCounter; i <= message.Counter; i++ {
			potentialCachedKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
			potentialMkeys[i] = potentialCachedKey
			tempRec := c.Sessions[*message.Sender].ReceiveChain
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			tempRec.Zeroize()

			c.Sessions[*message.Sender].ReceiveCounter++
		}
		c.Sessions[*message.Sender].ReceiveCounter--
	}

	messageKey = potentialMkeys[c.Sessions[*message.Sender].ReceiveCounter] //Gets last key we generated.
	decipheredText, err := messageKey.AuthenticatedDecrypt((*message).Ciphertext, message.EncodeAdditionalData(), (*message).IV)

	if err != nil { //Means cipher text of last message has been tamperd with has been tamperd with

		c.Sessions[*message.Sender].RootChain.Zeroize() //Zeroise comprimised keys.
		c.Sessions[*message.Sender].ReceiveChain.Zeroize()

		c.Sessions[*message.Sender].RootChain = oldRoot   //Reset state
		c.Sessions[*message.Sender].ReceiveChain = oldRec //Always reset Rec chain if error. Even if derive root or not
		c.Sessions[*message.Sender].LastAction = prevAction
		c.Sessions[*message.Sender].ReceiveCounter = oldRecVal
		c.Sessions[*message.Sender].PartnerDHRatchet = oldPartnerDHRatchet

		for key, val := range potentialMkeys { //zero messageKey as it points to the same key as in the map. And all cached keys didn't happen.
			val.Zeroize()
			delete(potentialMkeys, key)
		}
		return "", errors.New("Cipher text has been modified - break2")
	}
	messageKey.Zeroize()                                               //Zero message key here, messageKey is also zerod in the for loop within the above if statemnt.
	delete(potentialMkeys, c.Sessions[*message.Sender].ReceiveCounter) //Now we can delete key we just used, may be zerod if error occurs

	oldRoot.Zeroize()
	oldRec.Zeroize()
	for key, val := range potentialMkeys { //If deryption of last message is succesful add all keys to cache
		c.Sessions[*message.Sender].CachedReceiveKeys[key] = val
		delete(potentialMkeys, key)
	}

	return decipheredText, nil
}
