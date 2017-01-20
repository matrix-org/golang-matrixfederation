package gomatrixserverlib

import (
	"encoding/json"
)

// rawJSON is a reimplementation of json.RawMessage that supports being used as a value type
//
// For example:
//
//  jsonBytes, _ := json.Marshal(struct{
//		RawMessage json.RawMessage
//		RawJSON rawJSON
//	}{
//		json.RawMessage(`"Hello"`),
//		rawJSON(`"World"`),
//	})
//
// Results in:
//
//  {"RawMessage":"IkhlbGxvIg==","RawJSON":"World"}
//
// See https://play.golang.org/p/FzhKIJP8-I for a full example.
type rawJSON []byte

// MarshalJSON implements the json.Marshaller interface using a value receiver.
// This means that rawJSON used as an embedded value will still encode correctly.
func (r rawJSON) MarshalJSON() ([]byte, error) {
	return []byte(r), nil
}

// UnmarshalJSON implements the json.Unmarshaller interface using a pointer receiver.
func (r *rawJSON) UnmarshalJSON(data []byte) error {
	*r = rawJSON(data)
	return nil
}

// RedactEvent strips the user controlled fields from an event, but leaves the
// fields necessary for authenticating the event.
func RedactEvent(eventJSON []byte) ([]byte, error) {

	// createContent keeps the fields needed in a m.room.create event.
	// Create events need to keep the creator.
	// (In an ideal world they would keep the m.federate flag see matrix-org/synapse#1831)
	type createContent struct {
		Creator rawJSON `json:"creator,omitempty"`
	}

	// joinRulesContent keeps the fields needed in a m.room.join_rules event.
	// Join rules events need to keep the join_rule key.
	type joinRulesContent struct {
		JoinRule rawJSON `json:"join_rule,omitempty"`
	}

	// powerLevelContent keeps the fields needed in a m.room.power_levels event.
	// Power level events need to keep all the levels.
	type powerLevelContent struct {
		Users         rawJSON `json:"users,omitempty"`
		UsersDefault  rawJSON `json:"users_default,omitempty"`
		Events        rawJSON `json:"events,omitempty"`
		EventsDefault rawJSON `json:"events_default,omitempty"`
		StateDefault  rawJSON `json:"state_default,omitempty"`
		Ban           rawJSON `json:"ban,omitempty"`
		Kick          rawJSON `json:"kick,omitempty"`
		Redact        rawJSON `json:"redact,omitempty"`
	}

	// memberContent keeps the fields needed in a m.room.member event.
	// Member events keep the membership.
	// (In an ideal world they would keep the third_party_invite see matrix-org/synapse#1831)
	type memberContent struct {
		Membership rawJSON `json:"membership,omitempty"`
	}

	// aliasesContent keeps the fields needed in a m.room.aliases event.
	// TODO: Alias events probably don't need to keep the aliases key, but we need to match synapse here.
	type aliasesContent struct {
		Aliases rawJSON `json:"aliases,omitempty"`
	}

	// historyVisibilityContent keeps the fields needed in a m.room.history_visibility event
	// History visibility events need to keep the history_visibility key.
	type historyVisibilityContent struct {
		HistoryVisibility rawJSON `json:"history_visibility,omitempty"`
	}

	// allContent keeps the union of all the content fields needed across all the event types.
	// All the content JSON keys we are keeping are distinct across the different event types.
	type allContent struct {
		createContent
		joinRulesContent
		powerLevelContent
		memberContent
		aliasesContent
		historyVisibilityContent
	}

	// eventFields keeps the top level keys needed by all event types.
	// (In an ideal world they would include the "redacts" key for m.room.redaction events, see matrix-org/synapse#1831)
	// See https://github.com/matrix-org/synapse/blob/v0.18.7/synapse/events/utils.py#L42-L56 for the list of fields
	type eventFields struct {
		EventID        rawJSON    `json:"event_id,omitempty"`
		Sender         rawJSON    `json:"sender,omitempty"`
		RoomID         rawJSON    `json:"room_id,omitempty"`
		Hashes         rawJSON    `json:"hashes,omitempty"`
		Signatures     rawJSON    `json:"signatures,omitempty"`
		Content        allContent `json:"content"`
		Type           string     `json:"type"`
		StateKey       rawJSON    `json:"state_key,omitempty"`
		Depth          rawJSON    `json:"depth,omitempty"`
		PrevEvents     rawJSON    `json:"prev_events,omitempty"`
		PrevState      rawJSON    `json:"prev_state,omitempty"`
		AuthEvents     rawJSON    `json:"auth_events,omitempty"`
		Origin         rawJSON    `json:"origin,omitempty"`
		OriginServerTS rawJSON    `json:"origin_server_ts,omitempty"`
		Membership     rawJSON    `json:"membership,omitempty"`
	}

	var event eventFields
	// Unmarshalling into a struct will discard any extra fields from the event.
	if err := json.Unmarshal(eventJSON, &event); err != nil {
		return nil, err
	}
	var newContent allContent
	// Copy the content fields that we should keep for the event type.
	// By default we copy nothing leaving the content object empty.
	switch event.Type {
	case "m.room.create":
		newContent.createContent = event.Content.createContent
	case "m.room.member":
		newContent.memberContent = event.Content.memberContent
	case "m.room.join_rules":
		newContent.joinRulesContent = event.Content.joinRulesContent
	case "m.room.power_levels":
		newContent.powerLevelContent = event.Content.powerLevelContent
	case "m.room.history_visibility":
		newContent.historyVisibilityContent = event.Content.historyVisibilityContent
	case "m.room.aliases":
		newContent.aliasesContent = event.Content.aliasesContent
	}
	// Replace the content with our new filtered content.
	// This will zero out any keys that weren't copied in the switch statement above.
	event.Content = newContent
	// Return the redacted event encoded as JSON.
	return json.Marshal(&event)
}
