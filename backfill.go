package gomatrixserverlib

import (
	"context"
	"fmt"
)

// BackfillRequester contains the necessary functions to perform backfill requests from one server to another.
type BackfillRequester interface {
	// ServersAtEvent is called when trying to determine which server to request from.
	// It returns a list of servers which can be queried for backfill requests. These servers
	// will be servers that are in the room already. The entries at the beginning are preferred servers
	// and will be tried first. An empty list will fail the request.
	ServersAtEvent(ctx context.Context, roomID, eventID string) []ServerName
	// Backfill performs a backfill request to the given server.
	// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-backfill-roomid
	Backfill(ctx context.Context, server ServerName, roomID string, fromEventIDs []string, limit int) (*Transaction, error)
	// StateIDs performs a state IDs request to the given server.
	// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-state-ids-roomid
	StateIDs(ctx context.Context, server ServerName, roomID, eventID string) (*RespStateIDs, error)
	// EventAuth performs an event auth request to the given server.
	// https://matrix.org/docs/spec/server_server/latest#get-matrix-federation-v1-event-auth-roomid-eventid
	EventAuth(ctx context.Context, server ServerName, roomID, eventID string) (*RespEventAuth, error)
}

// RequestBackfill implements the server logic for making backfill requests to other servers.
// This handles server selection, fetching up to the request limit and verifying the received events.
// Event validation also includes authorisation checks, which may require additional state to be fetched.
//
// The returned events are safe to be inserted into a database for later retrieval. It's possible for the
// number of returned events to be less than the limit, even if there exists more events. It's also possible
// for the number of returned events to be greater than the limit, if fromEventIDs > 1 and we need to ask
// multiple servers. We don't drop events greater than the limit because we've already done all the work to
// verify them, so it's up to the caller to decide what to do with them.
//
// TODO: We should be able to make some guarantees for the caller about the returned events position in the DAG,
// but to verify it we need to know the prev_events of fromEventIDs.
//
// TODO: When does it make sense to return errors?
func RequestBackfill(ctx context.Context, b BackfillRequester, keyRing JSONVerifier,
	roomID string, ver RoomVersion, fromEventIDs []string, limit int) ([]HeaderedEvent, error) {

	if len(fromEventIDs) == 0 {
		return nil, nil
	}
	haveEventIDs := make(map[string]bool)
	var result []HeaderedEvent
	// pick a server to backfill from
	// TODO: use other event IDs and make a set out of all the returned servers?
	servers := b.ServersAtEvent(ctx, roomID, fromEventIDs[0])
	// loop each server asking it for `limit` events. Worst case, we ask every server for `limit`
	// events before giving up. Best case, we just ask one.
	for _, s := range servers {
		if len(result) >= limit {
			break
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("gomatrixserverlib: RequestBackfill context cancelled %w", ctx.Err())
		}
		// fetch some events, and try a different server if it fails
		txn, err := b.Backfill(ctx, s, roomID, fromEventIDs, limit)
		if err != nil {
			continue // try the next server
		}
		headered, err := verifiedEventsFromTransaction(ctx, txn, ver, keyRing)
		if err != nil {
			continue // try the next server
		}
		for _, h := range headered {
			if haveEventIDs[h.EventID()] {
				continue // we got this event from a different server
			}
			haveEventIDs[h.EventID()] = true
			result = append(result, h)
		}
	}

	return result, nil
}

// verifiedEventsFromTransaction returns only the verified events from the provided transaction, dropping the rest.
func verifiedEventsFromTransaction(ctx context.Context, txn *Transaction, ver RoomVersion, keyRing JSONVerifier) ([]HeaderedEvent, error) {
	// validate the content hashes
	var events []Event
	for _, p := range txn.PDUs {
		event, err := NewEventFromUntrustedJSON(p, ver)
		if err != nil {
			// skip over bad events
			continue
		}
		events = append(events, event)
	}
	failures, err := VerifyEventSignatures(ctx, events, keyRing)
	if err != nil {
		return nil, err
	}
	if len(failures) != len(events) {
		return nil, fmt.Errorf("gomatrixserverlib: bulk event signature verification length mismatch: %d != %d", len(failures), len(events))
	}
	var headered []HeaderedEvent
	for i := range events {
		if eventErr := failures[i]; eventErr != nil {
			// skip over bad events, we'll fetch them from somewhere else
			continue
		}
		headered = append(headered, events[i].Headered(ver))
	}

	// TODO: check auth and recurse through auth_events, calling /state_ids for missing events

	return headered, nil
}

/*
// BackfillResponder contains the necessary functions to handle backfill requests.
type backfillResponder interface {
	// TODO, unexported for now.
}

// ReceiveBackfill implements the server logic for processing backfill requests sent by a server.
// This handles event selection via breadth-first search, as well as history visibility rules depending
// on the state of the room at that point in time.
func receiveBackfill(b backfillResponder, roomID string, fromEventIDs []string, limit int) (*Transaction, error) {
	return nil, nil // TODO, unexported for now.
}
*/
