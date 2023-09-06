// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// debugHandshake, if set, prints messages sent and received.  Key
// exchange messages are printed as if DH were used, so the debug
// messages are wrong when using ECDH.
const debugHandshake = false

// chanSize sets the amount of buffering SSH connections. This is
// primarily for testing: setting chanSize=0 uncovers deadlocks more
// quickly.
const chanSize = 16

// keyingTransport is a packet based transport that supports key
// changes. It need not be thread-safe. It should pass through
// msgNewKeys in both directions.
type keyingTransport interface {
	packetConn

	// prepareKeyChange sets up a key change. The key change for a
	// direction will be effected if a msgNewKeys message is sent
	// or received.
	prepareKeyChange(*algorithms, *kexResult) error

	getSequenceNumbers() (outgoing uint32, incoming uint32)
	setOutgoingSequenceNumber(uint32)
	setIncomingSequenceNumber(uint32)
}

// handshakeTransport implements rekeying on top of a keyingTransport
// and offers a thread-safe writePacket() interface.
type handshakeTransport struct {
	conn   keyingTransport
	config *Config

	serverVersion []byte
	clientVersion []byte

	// hostKeys is non-empty if we are the server. In that case,
	// it contains all host keys that can be used to sign the
	// connection.
	hostKeys []Signer

	// hostKeyAlgorithms is non-empty if we are the client. In that case,
	// we accept these key types from the server as host key.
	hostKeyAlgorithms []string

	// On read error, incoming is closed, and readError is set.
	incoming           chan []byte
	lastIncomingSeqNum uint32
	readError          error

	mu             sync.Mutex
	writeError     error
	sentInitPacket []byte
	sentInitMsg    *kexInitMsg
	pendingPackets [][]byte // Used when a key exchange is in progress.

	// If the read loop wants to schedule a kex, it pings this
	// channel, and the write loop will send out a kex
	// message.
	requestKex chan struct{}

	// If the other side requests or confirms a kex, its kexInit
	// packet is sent here for the write loop to find it.
	startKex chan *pendingKex

	stopOutKex chan chan<- struct{}
	stopInKex  chan struct{}

	responsibleForKex bool
	kexCallback       KexCallback

	// data for host key checking
	hostKeyCallback          HostKeyCallback
	dialAddress              string
	remoteAddr               net.Addr
	deferHostKeyVerification bool

	// Algorithms agreed in the last key exchange.
	algorithms *algorithms

	readPacketsLeft uint32
	readBytesLeft   int64

	writePacketsLeft uint32
	writeBytesLeft   int64

	// The session ID or nil if first kex did not complete yet.
	sessionID []byte

	pendingSeqNumDelta uint32
}

type pendingKex struct {
	otherInit []byte
	done      chan error
}

func newHandshakeTransport(conn keyingTransport, config *Config, clientVersion, serverVersion []byte) *handshakeTransport {
	t := &handshakeTransport{
		conn:               conn,
		serverVersion:      serverVersion,
		clientVersion:      clientVersion,
		incoming:           make(chan []byte, chanSize),
		requestKex:         make(chan struct{}, 1),
		startKex:           make(chan *pendingKex, 1),
		stopOutKex:         make(chan chan<- struct{}, 1),
		stopInKex:          make(chan struct{}, 1),
		config:             config,
		lastIncomingSeqNum: 0,
		responsibleForKex:  true,
		kexCallback:        config.KexCallback,
	}
	t.resetReadThresholds()
	t.resetWriteThresholds()

	// We always start with a mandatory key exchange.
	t.requestKex <- struct{}{}
	return t
}

func newClientTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ClientConfig, dialAddr string, addr net.Addr) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.dialAddress = dialAddr
	t.remoteAddr = addr
	t.hostKeyCallback = config.HostKeyCallback
	t.deferHostKeyVerification = config.DeferHostKeyVerification
	if config.HostKeyAlgorithms != nil {
		t.hostKeyAlgorithms = config.HostKeyAlgorithms
	} else {
		t.hostKeyAlgorithms = supportedHostKeyAlgos
	}
	go t.readLoop()
	go t.kexLoop()
	return t
}

func newServerTransport(conn keyingTransport, clientVersion, serverVersion []byte, config *ServerConfig) *handshakeTransport {
	t := newHandshakeTransport(conn, &config.Config, clientVersion, serverVersion)
	t.hostKeys = config.hostKeys
	go t.readLoop()
	go t.kexLoop()
	return t
}

func (t *handshakeTransport) getSessionID() []byte {
	return t.sessionID
}

const updateSessionParamsReqId = "updateSessionParams@cs.stanford.edu"
const confirmSessionParamsReqId = "confirmSessionParams@cs.stanford.edu"

type updateSessionParams struct {
	DeltaC2S  uint32
	DeltaS2C  uint32
	SessionID []byte
}

func (t *handshakeTransport) updateSessionParams(sessionID []byte, outSeqNum uint32, inSeqNum uint32) error {
	t.sessionID = sessionID

	oldOut, oldIn := t.getSequenceNumbers()

	t.pendingSeqNumDelta = inSeqNum - oldIn

	err := t.pushPacket(
		Marshal(globalRequestMsg{
			Type:      updateSessionParamsReqId,
			WantReply: false, // Don't use the standard request confirmation mechanism
			Data: Marshal(updateSessionParams{
				DeltaC2S:  t.pendingSeqNumDelta,
				DeltaS2C:  outSeqNum - oldOut - 1, // Off by one because of the update packet itself
				SessionID: sessionID,
			}),
		}))

	if err != nil {
		return err
	}

	t.conn.setOutgoingSequenceNumber(outSeqNum)
	return nil
}

func (t *handshakeTransport) handleSessionParamsUpdates(sessionID []byte, deltaOut uint32, deltaIn uint32) error {
	t.sessionID = sessionID

	t.mu.Lock()
	defer t.mu.Unlock()

	err := t.pushPacket(
		Marshal(globalRequestMsg{
			Type:      confirmSessionParamsReqId,
			WantReply: false,
		}),
	)

	if err != nil {
		return err
	}

	outSeqNum, inSeqNum := t.conn.getSequenceNumbers()
	t.conn.setIncomingSequenceNumber(inSeqNum + deltaIn)
	t.conn.setOutgoingSequenceNumber(outSeqNum + deltaOut)
	return nil
}

func (t *handshakeTransport) getSequenceNumbers() (out uint32, in uint32) {
	out, _ = t.conn.getSequenceNumbers()
	return out, t.lastIncomingSeqNum - uint32(len(t.incoming))
}

// waitSession waits for the session to be established. This should be
// the first thing to call after instantiating handshakeTransport.
func (t *handshakeTransport) waitSession() error {
	p, err := t.readPacket()
	if err != nil {
		return err
	}
	if p[0] != msgNewKeys {
		return fmt.Errorf("ssh: first packet should be msgNewKeys")
	}

	return nil
}

func (t *handshakeTransport) id() string {
	if len(t.hostKeys) > 0 {
		return "server"
	}
	return "client"
}

func (t *handshakeTransport) printPacket(p []byte, write bool) {
	action := "got"
	if write {
		action = "sent"
	}

	if p[0] == msgChannelData || p[0] == msgChannelExtendedData {
		log.Printf("%s %s data (packet %d bytes)", t.id(), action, len(p))
	} else {
		msg, err := decode(p)
		log.Printf("%s %s %T %v (%v)", t.id(), action, msg, msg, err)
	}
}

func (t *handshakeTransport) readPacket() ([]byte, error) {
	p, ok := <-t.incoming
	if !ok {
		return nil, t.readError
	}
	return p, nil
}

func (t *handshakeTransport) readLoop() {
	first := true
	for {
		p, err := t.readOnePacket(first)
		first = false
		if err != nil {
			t.readError = err
			close(t.incoming)
			break
		}
		if t.responsibleForKex && len(p) >= 0 && (p[0] == msgDebug || p[0] == msgIgnore) {
			continue
		}
		t.incoming <- p
		_, in := t.conn.getSequenceNumbers()
		t.lastIncomingSeqNum = in
		// If not responsible for KEX, then new keys terminates this connection
		// (since the new keys will no longer be recognized).
		if p[0] == msgNewKeys && !t.responsibleForKex {
			break
		}
	}

	// Stop writers too.
	t.recordWriteError(t.readError)

	// Unblock the writer should it wait for this (only if responsibleForKex)
	if t.responsibleForKex {
		close(t.startKex)
	}

	// Don't close t.requestKex; it's also written to from writePacket.
}

func (t *handshakeTransport) pushPacket(p []byte) error {
	if debugHandshake {
		t.printPacket(p, true)
	}
	return t.conn.writePacket(p)
}

func (t *handshakeTransport) getWriteError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writeError
}

func (t *handshakeTransport) recordWriteError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeError == nil && err != nil {
		t.writeError = err
	}
}

func (t *handshakeTransport) requestKeyExchange() {
	log.Printf("requestKeyExchange, t.deferHostKeyVerification: %b", t.deferHostKeyVerification)
	if t.deferHostKeyVerification {
		// Don't initiate kex when in deferred mode
		return
	}
	select {
	case t.requestKex <- struct{}{}:
	default:
		// something already requested a kex, so do nothing.
	}
}

func (t *handshakeTransport) resetWriteThresholds() {
	t.writePacketsLeft = packetRekeyThreshold
	if t.config.RekeyThreshold > 0 {
		t.writeBytesLeft = int64(t.config.RekeyThreshold)
	} else if t.algorithms != nil {
		t.writeBytesLeft = t.algorithms.w.rekeyBytes()
	} else {
		t.writeBytesLeft = 1 << 30
	}
}

func (t *handshakeTransport) kexLoop() {
	var onStop chan<- struct{}
	requestKex := t.requestKex

write:
	for t.getWriteError() == nil {
		log.Printf("kex loop")
		var request *pendingKex
		var sent bool

		for request == nil || !sent {
			log.Printf("kex inner loop")
			var ok bool
			select {
			case request, ok = <-t.startKex:
				if !ok {
					log.Printf("select exit: <-t.startKex NOT OK")
					break write
				}
				log.Printf("select exit: <-t.startKex")
			case <-requestKex:
				log.Printf("select exit: <-requestKex")
				break
			case onStop = <-t.stopOutKex:
				log.Printf("select exit: <-t.stopOutKex")
				// Don't listen on new requests for outgoing kex,
				// so no new outoing kex will be initiated
				requestKex = nil

				if !sent {
					// If not awaiting a reply to an outgoing kex,
					// stop incoming kex messages as well.
					t.stopInKex <- struct{}{}
				}
				// Continue in case there are existing messages in startKex
				continue
			}
			// If kex is being cancelled, then stop incoming messages after
			// this one.
			if requestKex == nil {
				t.stopInKex <- struct{}{}
			}

			if !sent {
				log.Printf("!sent: sending kexInit")
				if err := t.sendKexInit(); err != nil {
					t.recordWriteError(err)
					break
				}
				sent = true
			}
		}

		if err := t.getWriteError(); err != nil {
			if request != nil {
				request.done <- err
			}
			break
		}

		// We're not servicing t.requestKex, but that is OK:
		// we never block on sending to t.requestKex.

		// We're not servicing t.startKex, but the remote end
		// has just sent us a kexInitMsg, so it can't send
		// another key change request, until we close the done
		// channel on the pendingKex request.
		log.Printf("entering keyexchange")

		err := t.enterKeyExchange(request.otherInit)

		t.mu.Lock()
		t.writeError = err
		t.sentInitPacket = nil
		t.sentInitMsg = nil

		t.resetWriteThresholds()

		// we have completed the key exchange. Since the
		// reader is still blocked, it is safe to clear out
		// the requestKex channel. This avoids the situation
		// where: 1) we consumed our own request for the
		// initial kex, and 2) the kex from the remote side
		// caused another send on the requestKex channel,
	clear:
		for {
			select {
			case <-t.requestKex:
				//
			default:
				break clear
			}
		}

		if t.writeError == nil && t.kexCallback != nil {
			t.kexCallback()
		}

		request.done <- t.writeError

		// kex finished. Push packets that we received while
		// the kex was in progress. Don't look at t.startKex
		// and don't increment writtenSinceKex: if we trigger
		// another kex while we are still busy with the last
		// one, things will become very confusing.
		for _, p := range t.pendingPackets {
			t.writeError = t.pushPacket(p)
			if t.writeError != nil {
				break
			}
		}
		t.pendingPackets = t.pendingPackets[:0]
		t.mu.Unlock()
	}

	// drain startKex channel. We don't service t.requestKex
	// because nobody does blocking sends there.
	go func() {
		for init := range t.startKex {
			init.done <- t.writeError
		}
	}()

	// Unblock reader.
	if t.writeError != nil {
		t.conn.Close()
	}
	if onStop != nil {
		onStop <- struct{}{}
	}
}

// The protocol uses uint32 for packet counters, so we can't let them
// reach 1<<32.  We will actually read and write more packets than
// this, though: the other side may send more packets, and after we
// hit this limit on writing we will send a few more packets for the
// key exchange itself.
const packetRekeyThreshold = (1 << 31)

func (t *handshakeTransport) resetReadThresholds() {
	t.readPacketsLeft = packetRekeyThreshold
	if t.config.RekeyThreshold > 0 {
		t.readBytesLeft = int64(t.config.RekeyThreshold)
	} else if t.algorithms != nil {
		t.readBytesLeft = t.algorithms.r.rekeyBytes()
	} else {
		t.readBytesLeft = 1 << 30
	}
}

func (t *handshakeTransport) readOnePacket(first bool) ([]byte, error) {
	packetCh := make(chan []byte)
	errCh := make(chan error)
	go func() {
		if p, err := t.conn.readPacket(); err != nil {
			errCh <- err
		} else {
			packetCh <- p
		}
	}()

	var p []byte
	for p == nil {
		select {
		case <-t.stopInKex:
			close(t.startKex)
			t.responsibleForKex = false
		case err := <-errCh:
			return nil, err
		case p = <-packetCh:
		}

	}

	if t.readPacketsLeft > 0 {
		t.readPacketsLeft--
	} else {
		t.requestKeyExchange()
	}

	if t.readBytesLeft > 0 {
		t.readBytesLeft -= int64(len(p))
	} else {
		t.requestKeyExchange()
	}

	if debugHandshake {
		t.printPacket(p, false)
	}

	if p[0] == msgGlobalRequest {
		var msg globalRequestMsg
		if err := Unmarshal(p, &msg); err != nil {
			return nil, err
		}
		switch msg.Type {
		case confirmSessionParamsReqId:
			_, inSeqNum := t.conn.getSequenceNumbers()
			t.conn.setIncomingSequenceNumber(inSeqNum + t.pendingSeqNumDelta)
			successPacket := []byte{msgIgnore}
			return successPacket, nil
		case updateSessionParamsReqId:
			reqData := new(updateSessionParams)
			if err := Unmarshal(msg.Data, reqData); err != nil {
				log.Printf("Failed to unmarshal updateSessionParams %s", err)
				return nil, err
			}
			t.handleSessionParamsUpdates(reqData.SessionID, reqData.DeltaC2S, reqData.DeltaS2C)
			successPacket := []byte{msgIgnore}
			return successPacket, nil
		}
	}

	if first && p[0] != msgKexInit {
		return nil, fmt.Errorf("ssh: first packet should be msgKexInit")
	}

	if p[0] != msgKexInit || !t.responsibleForKex {
		return p, nil
	}

	firstKex := t.sessionID == nil

	kex := pendingKex{
		done:      make(chan error, 1),
		otherInit: p,
	}
	t.startKex <- &kex
	err := <-kex.done

	if debugHandshake {
		log.Printf("%s exited key exchange (first %v), err %v", t.id(), firstKex, err)
	}

	if err != nil {
		return nil, err
	}

	t.resetReadThresholds()

	// By default, a key exchange is hidden from higher layers by
	// translating it into msgIgnore.
	successPacket := []byte{msgIgnore}
	if firstKex {
		// sendKexInit() for the first kex waits for
		// msgNewKeys so the authentication process is
		// guaranteed to happen over an encrypted transport.
		successPacket = []byte{msgNewKeys}
	}

	return successPacket, nil
}

// sendKexInit sends a key change message.
func (t *handshakeTransport) sendKexInit() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sentInitMsg != nil {
		// kexInits may be sent either in response to the other side,
		// or because our side wants to initiate a key change, so we
		// may have already sent a kexInit. In that case, don't send a
		// second kexInit.
		return nil
	}

	msg := &kexInitMsg{
		KexAlgos:                t.config.KeyExchanges,
		CiphersClientServer:     t.config.Ciphers,
		CiphersServerClient:     t.config.Ciphers,
		MACsClientServer:        t.config.MACs,
		MACsServerClient:        t.config.MACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	io.ReadFull(rand.Reader, msg.Cookie[:])

	if t.deferHostKeyVerification {
		msg.ServerHostKeyAlgos = []string{KeyAlgoNone}
	} else if len(t.hostKeys) > 0 {
		for _, k := range t.hostKeys {
			msg.ServerHostKeyAlgos = append(
				msg.ServerHostKeyAlgos, k.PublicKey().Type())
		}
	} else {
		msg.ServerHostKeyAlgos = t.hostKeyAlgorithms
	}
	packet := Marshal(msg)

	// writePacket destroys the contents, so save a copy.
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	if err := t.pushPacket(packetCopy); err != nil {
		return err
	}

	t.sentInitMsg = msg
	t.sentInitPacket = packet

	return nil
}

func (t *handshakeTransport) writePacket(p []byte) error {
	if t.responsibleForKex {
		switch p[0] {
		case msgKexInit:
			return errors.New("ssh: only handshakeTransport can send kexInit")
		case msgNewKeys:
			return errors.New("ssh: only handshakeTransport can send newKeys")
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.writeError != nil {
		return t.writeError
	}

	if t.sentInitMsg != nil {
		// Copy the packet so the writer can reuse the buffer.
		cp := make([]byte, len(p))
		copy(cp, p)
		t.pendingPackets = append(t.pendingPackets, cp)
		return nil
	}

	if t.writeBytesLeft > 0 {
		t.writeBytesLeft -= int64(len(p))
	} else {
		t.requestKeyExchange()
	}

	if t.writePacketsLeft > 0 {
		t.writePacketsLeft--
	} else {
		t.requestKeyExchange()
	}

	if err := t.pushPacket(p); err != nil {
		t.writeError = err
	}

	return nil
}

func (t *handshakeTransport) Close() error {
	return t.conn.Close()
}

func (t *handshakeTransport) enterKeyExchange(otherInitPacket []byte) error {
	if debugHandshake {
		log.Printf("%s entered key exchange", t.id())
	}

	otherInit := &kexInitMsg{}
	if err := Unmarshal(otherInitPacket, otherInit); err != nil {
		return err
	}

	magics := handshakeMagics{
		clientVersion: t.clientVersion,
		serverVersion: t.serverVersion,
		clientKexInit: otherInitPacket,
		serverKexInit: t.sentInitPacket,
	}

	clientInit := otherInit
	serverInit := t.sentInitMsg
	if len(t.hostKeys) == 0 {
		clientInit, serverInit = serverInit, clientInit

		magics.clientKexInit = t.sentInitPacket
		magics.serverKexInit = otherInitPacket
	}

	var err error
	t.algorithms, err = findAgreedAlgorithms(clientInit, serverInit)
	if err != nil {
		return err
	}

	// We don't send FirstKexFollows, but we handle receiving it.
	//
	// RFC 4253 section 7 defines the kex and the agreement method for
	// first_kex_packet_follows. It states that the guessed packet
	// should be ignored if the "kex algorithm and/or the host
	// key algorithm is guessed wrong (server and client have
	// different preferred algorithm), or if any of the other
	// algorithms cannot be agreed upon". The other algorithms have
	// already been checked above so the kex algorithm and host key
	// algorithm are checked here.
	if otherInit.FirstKexFollows && (clientInit.KexAlgos[0] != serverInit.KexAlgos[0] || clientInit.ServerHostKeyAlgos[0] != serverInit.ServerHostKeyAlgos[0]) {
		// other side sent a kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := t.conn.readPacket(); err != nil {
			return err
		}
	}

	kex, ok := kexAlgoMap[t.algorithms.kex]
	if !ok {
		return fmt.Errorf("ssh: unexpected key exchange algorithm %v", t.algorithms.kex)
	}

	var result *kexResult
	if len(t.hostKeys) > 0 {
		result, err = t.server(kex, t.algorithms, &magics)
	} else {
		result, err = t.client(kex, t.algorithms, &magics)
	}

	if err != nil {
		return err
	}

	if t.sessionID == nil {
		t.sessionID = result.H
	}
	result.SessionID = t.sessionID

	if err := t.conn.prepareKeyChange(t.algorithms, result); err != nil {
		return err
	}
	if err = t.conn.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if packet, err := t.conn.readPacket(); err != nil {
		return err
	} else if packet[0] != msgNewKeys {
		return unexpectedMessageError(msgNewKeys, packet[0])
	}

	return nil
}

func (t *handshakeTransport) server(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	var hostKey Signer
	for _, k := range t.hostKeys {
		if algs.hostKey == k.PublicKey().Type() {
			hostKey = k
		}
	}

	r, err := kex.Server(t.conn, t.config.Rand, magics, hostKey)
	return r, err
}

func (t *handshakeTransport) client(kex kexAlgorithm, algs *algorithms, magics *handshakeMagics) (*kexResult, error) {
	result, err := kex.Client(t.conn, t.config.Rand, magics)
	if err != nil {
		return nil, err
	}

	hostKey, err := ParsePublicKey(result.HostKey)
	if err != nil {
		return nil, err
	}

	if err := verifyHostKeySignature(hostKey, result); err != nil {
		return nil, err
	}

	err = t.hostKeyCallback(t.dialAddress, t.remoteAddr, hostKey)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (t *handshakeTransport) stopKexHandling(stopped chan<- struct{}) {
	t.stopOutKex <- stopped
}

func (t *handshakeTransport) buffered() int {
	return t.conn.buffered()
}
