package gomatrixserverlib

import (
	"encoding/json"
	"fmt"
)

// HeaderedEventHeader contains header fields for an event that contains
// additional metadata, e.g. room version.
type EventHeader struct {
	RoomVersion RoomVersion `json:"room_version"`
}

// HeaderedEvent is a wrapper around an Event that contains information
// about the room version.
type HeaderedEvent struct {
	EventHeader
	Event
}

// UnmarshalJSON implements json.Unmarshaller
func (e *HeaderedEvent) UnmarshalJSON(data []byte) error {
	var m EventHeader
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	switch m.RoomVersion {
	case RoomVersionV1, RoomVersionV2:
		fmt.Println("room v1 or v2")
	case RoomVersionV3, RoomVersionV4, RoomVersionV5:
		fmt.Println("room v3 or v4 or v5")
	default:
		return UnsupportedRoomVersionError{m.RoomVersion}
	}
	if err := json.Unmarshal(data, &e.Event); err != nil {
		return err
	}
	return nil
}