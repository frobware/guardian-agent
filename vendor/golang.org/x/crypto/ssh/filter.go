package ssh

import (
	"log"
)

const (
	Inactive = iota
	AwaitingReply
	Success
	Failure
)

type EscalateFunc func() error

type Filter struct {
	// kept to validate that promised command is made command (may be unecessary since we don't check thereafter if all approved)
	command       string
	sessionOpened bool
	nmsStatus     int
	escalate      EscalateFunc
}

func NewFilter(givenCommand string, escalate EscalateFunc) *Filter {
	return &Filter{
		command:  givenCommand,
		escalate: escalate,
	}
}

func (fil *Filter) FilterServerPacket(packet []byte) (validState bool, response []byte, err error) {
	if fil.nmsStatus != AwaitingReply {
		return true, nil, nil
	}

	switch packet[0] {
	case msgRequestSuccess:
		if debugProxy {
			log.Printf("Server approved no-more-sessions.")
		}
		fil.nmsStatus = Success
	case msgUnimplemented:
		fallthrough
	case msgRequestFailure:
		if debugProxy {
			log.Printf("Server sent no-more-sessions failure.")
		}
		fil.nmsStatus = Failure
	}
	return true, nil, nil
}

func (fil *Filter) FilterClientPacket(packet []byte) (allowed bool, response []byte, err error) {
	decoded, err := decode(packet)
	if err != nil {
		return false, nil, err
	}

	switch msg := decoded.(type) {
	case *channelOpenMsg:
		if msg.ChanType != "session" || fil.sessionOpened {
			return false, Marshal(channelOpenFailureMsg{}), nil
		}
		fil.sessionOpened = true
		return true, nil, nil
	case *globalRequestMsg:
		if msg.Type != NoMoreSessionRequestName {
			return false, Marshal(globalRequestFailureMsg{}), nil
		}
		if debugProxy {
			log.Printf("Client sent no-more-sessions")
		}
		fil.nmsStatus = AwaitingReply
		return true, nil, nil
	case *channelRequestMsg:
		reqCmd := ""
		if msg.Request == "pty-req" {
			return true, nil, nil
		}
		if msg.Request == "exec" {
			var execReq execMsg
			if err := Unmarshal(msg.RequestSpecificData, &execReq); err != nil {
				return false, nil, err
			}
			reqCmd = execReq.Command
		} else if msg.Request != "shell" {
			log.Printf("Channel request %s blocked (only 'exec'/'shell' is allowed)", msg.Request)
			return false, Marshal(channelRequestFailureMsg{}), nil
		}
		if reqCmd != fil.command {
			log.Printf("Unexpected command: %s, (expecting: %s)", reqCmd, fil.command)
			return false, Marshal(channelRequestFailureMsg{}), nil
		}
		return true, nil, nil
	case *kexInitMsg:
		if fil.nmsStatus == Success {
			return true, nil, nil
		}
		log.Printf("Attempting handoff without successful no-more-sessions.")
		err = fil.escalate()
		if err == nil {
			return true, nil, nil
		}
		reason := "Must issue no-more-sessions before handoff"
		if fil.nmsStatus == Failure {
			reason = "Server does not support fine-grained permissions, and user denied full access"
		}
		return false, Marshal(disconnectMsg{Reason: 2, Message: reason}), err
	default:
		return true, nil, nil
	}
}
