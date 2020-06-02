package gomatrixserverlib

import "fmt"

// RoomVersion refers to the room version for a specific room.
type RoomVersion string

// StateResAlgorithm refers to a version of the state resolution algorithm.
type StateResAlgorithm int

// EventFormat refers to the formatting of the event fields struct.
type EventFormat int

// EventIDFormat refers to the formatting used to generate new event IDs.
type EventIDFormat int

// Room version constants. These are strings because the version grammar
// allows for future expansion.
// https://matrix.org/docs/spec/#room-version-grammar
const (
	RoomVersionV1 RoomVersion = "1"
	RoomVersionV2 RoomVersion = "2"
	RoomVersionV3 RoomVersion = "3"
	RoomVersionV4 RoomVersion = "4"
	RoomVersionV5 RoomVersion = "5"
)

// Event format constants.
const (
	EventFormatV1 EventFormat = iota + 1 // prev_events and auth_events as event references
	EventFormatV2                        // prev_events and auth_events as string array of event IDs
)

// Event ID format constants.
const (
	EventIDFormatV1 EventIDFormat = iota + 1 // randomised
	EventIDFormatV2                          // base64-encoded hash of event
	EventIDFormatV3                          // URL-safe base64-encoded hash of event
)

// State resolution constants.
const (
	StateResV1 StateResAlgorithm = iota + 1 // state resolution v1
	StateResV2                              // state resolution v2
)

var roomVersionMeta = map[RoomVersion]RoomVersionDescription{
	RoomVersionV1: {
		Supported:              true,
		Stable:                 true,
		stateResAlgorithm:      StateResV1,
		eventFormat:            EventFormatV1,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	RoomVersionV2: {
		Supported:              true,
		Stable:                 true,
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV1,
		eventIDFormat:          EventIDFormatV1,
		enforceSignatureChecks: false,
	},
	RoomVersionV3: {
		Supported:              true,
		Stable:                 true,
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV2,
		enforceSignatureChecks: false,
	},
	RoomVersionV4: {
		Supported:              true,
		Stable:                 true,
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: false,
	},
	RoomVersionV5: {
		Supported:              true,
		Stable:                 true,
		stateResAlgorithm:      StateResV2,
		eventFormat:            EventFormatV2,
		eventIDFormat:          EventIDFormatV3,
		enforceSignatureChecks: true,
	},
}

// RoomVersions returns information about room versions currently
// implemented by this commit of gomatrixserverlib.
func RoomVersions() map[RoomVersion]RoomVersionDescription {
	return roomVersionMeta
}

// SupportedRoomVersions returns a map of descriptions for room
// versions that are marked as supported.
func SupportedRoomVersions() map[RoomVersion]RoomVersionDescription {
	versions := make(map[RoomVersion]RoomVersionDescription)
	for id, version := range RoomVersions() {
		if version.Supported {
			versions[id] = version
		}
	}
	return versions
}

// StableRoomVersions returns a map of descriptions for room
// versions that are marked as stable.
func StableRoomVersions() map[RoomVersion]RoomVersionDescription {
	versions := make(map[RoomVersion]RoomVersionDescription)
	for id, version := range RoomVersions() {
		if version.Supported && version.Stable {
			versions[id] = version
		}
	}
	return versions
}

// RoomVersionDescription contains information about a given room version, e.g. which
// state resolution algorithm or event ID format to use.
// RoomVersionDescription contains information about a room version,
// namely whether it is marked as supported or stable in this server
// version, along with the state resolution algorith, event ID etc
// formats used.
//
// A version is supported if the server has some support for rooms
// that are this version. A version is marked as stable or unstable
// in order to hint whether the version should be used to clients
// calling the /capabilities endpoint.
// https://matrix.org/docs/spec/client_server/r0.6.0#get-matrix-client-r0-capabilities
type RoomVersionDescription struct {
	Supported              bool
	Stable                 bool
	stateResAlgorithm      StateResAlgorithm
	eventFormat            EventFormat
	eventIDFormat          EventIDFormat
	enforceSignatureChecks bool
}

// StateResAlgorithm returns the state resolution for the given room version.
func (v RoomVersion) StateResAlgorithm() (StateResAlgorithm, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.stateResAlgorithm, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// EventFormat returns the event format for the given room version.
func (v RoomVersion) EventFormat() (EventFormat, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.eventFormat, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// EventIDFormat returns the event ID format for the given room version.
func (v RoomVersion) EventIDFormat() (EventIDFormat, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.eventIDFormat, nil
	}
	return 0, UnsupportedRoomVersionError{v}
}

// StrictValidityChecking returns true if the given room version calls for
// strict signature checking (room version 5 and onward) or false otherwise.
func (v RoomVersion) StrictValidityChecking() (bool, error) {
	if r, ok := roomVersionMeta[v]; ok {
		return r.enforceSignatureChecks, nil
	}
	return false, UnsupportedRoomVersionError{v}
}

// UnsupportedRoomVersionError occurs when a call has been made with a room
// version that is not supported by this version of gomatrixserverlib.
type UnsupportedRoomVersionError struct {
	Version RoomVersion
}

func (e UnsupportedRoomVersionError) Error() string {
	return fmt.Sprintf("gomatrixserverlib: unsupported room version '%s'", e.Version)
}
