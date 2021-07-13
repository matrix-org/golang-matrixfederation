package gomatrixserverlib

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/matrix-org/util"
	"golang.org/x/crypto/ed25519"
)

// A PublicKeyLookupRequest is a request for a public key with a particular key ID.
type PublicKeyLookupRequest struct {
	// The server to fetch a key for.
	ServerName ServerName `json:"server_name"`
	// The ID of the key to fetch.
	KeyID KeyID `json:"key_id"`
}

// MarshalText turns the public key lookup request into a string format,
// which allows us to use it as a JSON map key.
func (r PublicKeyLookupRequest) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s/%s", r.ServerName, r.KeyID)), nil
}

// UnmarshalText turns the string format back into a public key lookup
// request, from a JSON map key.
func (r *PublicKeyLookupRequest) UnmarshalText(text []byte) error {
	parts := strings.SplitN(string(text), "/", 2)
	if len(parts) < 2 {
		return errors.New("expected at least one / separator in " + string(text))
	}
	r.ServerName, r.KeyID = ServerName(parts[0]), KeyID(parts[1])
	return nil
}

// PublicKeyNotExpired is a magic value for PublicKeyLookupResult.ExpiredTS:
// it indicates that this is an active key which has not yet expired
const PublicKeyNotExpired = Timestamp(0)

// PublicKeyNotValid is a magic value for PublicKeyLookupResult.ValidUntilTS:
// it is used when we don't have a validity period for this key. Most likely
// it is an old key with an expiry date.
const PublicKeyNotValid = Timestamp(0)

// A PublicKeyLookupResult is the result of looking up a server signing key.
type PublicKeyLookupResult struct {
	VerifyKey
	// if this key has expired, the time it stopped being valid for event signing in milliseconds.
	// if the key has not expired, the magic value PublicKeyNotExpired.
	ExpiredTS Timestamp `json:"expired_ts"`
	// When this result is valid until in milliseconds.
	// if the key has expired, the magic value PublicKeyNotValid.
	ValidUntilTS Timestamp `json:"valid_until_ts"`
}

// WasValidAt checks if this signing key is valid for an event signed at the
// given timestamp.
func (r PublicKeyLookupResult) WasValidAt(atTs Timestamp, strictValidityChecking bool) bool {
	if r.ExpiredTS != PublicKeyNotExpired {
		return atTs < r.ExpiredTS
	}
	if strictValidityChecking {
		if r.ValidUntilTS == PublicKeyNotValid {
			return false
		}
		// Servers MUST use the lesser of valid_until_ts and 7 days into the
		// future when determining if a key is valid.
		// https://matrix.org/docs/spec/rooms/v5#signing-key-validity-period
		sevenDaysFuture := time.Now().Add(time.Hour * 24 * 7)
		validUntilTS := r.ValidUntilTS.Time()
		if validUntilTS.After(sevenDaysFuture) {
			validUntilTS = sevenDaysFuture
		}
		if atTs.Time().After(validUntilTS) {
			return false
		}
	}
	return true
}

type PublicKeyNotaryLookupRequest struct {
	ServerKeys map[ServerName]map[KeyID]PublicKeyNotaryQueryCriteria `json:"server_keys"`
}

type PublicKeyNotaryQueryCriteria struct {
	MinimumValidUntilTS Timestamp `json:"minimum_valid_until_ts"`
}

// A KeyFetcher is a way of fetching public keys in bulk.
type KeyFetcher interface {
	// Lookup a batch of public keys.
	// Takes a map from (server name, key ID) pairs to timestamp.
	// The timestamp is when the keys need to be vaild up to.
	// Returns a map from (server name, key ID) pairs to server key objects for
	// that server name containing that key ID
	// The result may have fewer (server name, key ID) pairs than were in the request.
	// The result may have more (server name, key ID) pairs than were in the request.
	// Returns an error if there was a problem fetching the keys.
	FetchKeys(ctx context.Context, requests map[PublicKeyLookupRequest]Timestamp) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error)

	// FetcherName returns the name of this fetcher, which can then be used for
	// logging errors etc.
	FetcherName() string
}

// A KeyDatabase is a store for caching public keys.
type KeyDatabase interface {
	KeyFetcher
	// Add a block of public keys to the database.
	// Returns an error if there was a problem storing the keys.
	// A database is not required to rollback storing the all keys if some of
	// the keys aren't stored, and an in-progess store may be partially visible
	// to a concurrent FetchKeys(). This is acceptable since the database is
	// only used as a cache for the keys, so if a FetchKeys() races with a
	// StoreKeys() and some of the keys are missing they will be just be refetched.
	StoreKeys(ctx context.Context, results map[PublicKeyLookupRequest]PublicKeyLookupResult) error
}

// A KeyRing stores keys for matrix servers and provides methods for verifying JSON messages.
type KeyRing struct {
	KeyFetchers []KeyFetcher
	KeyDatabase KeyDatabase
}

// A VerifyJSONRequest is a request to check for a signature on a JSON message.
// A JSON message is valid for a server if the message has at least one valid
// signature from that server.
type VerifyJSONRequest struct {
	// The name of the matrix server to check for a signature for.
	ServerName ServerName
	// The millisecond posix timestamp the message needs to be valid at.
	AtTS Timestamp
	// The JSON bytes.
	Message []byte
	// Should validity signature checking be enabled? (Room version >= 5)
	StrictValidityChecking bool
}

// A VerifyJSONResult is the result of checking the signature of a JSON message.
type VerifyJSONResult struct {
	// Whether the message passed the signature checks.
	// This will be nil if the message passed the checks.
	// This will have an error if the message did not pass the checks.
	Error error
}

// A JSONVerifier is an object which can verify the signatures of JSON messages.
type JSONVerifier interface {
	// VerifyJSONs performs bulk JSON signature verification for a list of VerifyJSONRequests.
	// Returns a list of VerifyJSONResults with the same length and order as the request list.
	// The caller should check the Result field for each entry to see if it was valid.
	// Returns an error if there was a problem talking to the database or one of the other methods
	// of fetching the public keys.
	VerifyJSONs(ctx context.Context, requests []VerifyJSONRequest) ([]VerifyJSONResult, error)
}

// VerifyJSONs implements JSONVerifier.
func (k KeyRing) VerifyJSONs(ctx context.Context, requests []VerifyJSONRequest) ([]VerifyJSONResult, error) { // nolint: gocyclo
	logger := util.GetLogger(ctx)
	results := make([]VerifyJSONResult, len(requests))
	keyIDs := make([][]KeyID, len(requests))

	// Store the initial number of requests that were made. We'll remove
	// things from the requests array that we no longer need, but we later
	// need to check that we satisfied the full number of requests.
	numRequests := len(requests)

	for i := range requests {
		ids, err := ListKeyIDs(string(requests[i].ServerName), requests[i].Message)
		if err != nil {
			results[i].Error = fmt.Errorf("gomatrixserverlib: error extracting key IDs")
			continue
		}
		for _, keyID := range ids {
			if k.isAlgorithmSupported(keyID) {
				keyIDs[i] = append(keyIDs[i], keyID)
			}
		}
		if len(keyIDs[i]) == 0 {
			results[i].Error = fmt.Errorf(
				"gomatrixserverlib: not signed by %q with a supported algorithm", requests[i].ServerName,
			)
			continue
		}
		// Set a place holder error in the result field.
		// This will be unset if one of the signature checks passes.
		// This will be overwritten if one of the signature checks fails.
		// Therefore this will only remain in place if the keys couldn't be downloaded.
		results[i].Error = fmt.Errorf(
			"gomatrixserverlib: could not download key for %q", requests[i].ServerName,
		)
	}

	keyRequests := k.publicKeyRequests(requests, results, keyIDs)
	if len(keyRequests) == 0 {
		// There aren't any keys to fetch so we can stop here.
		// This will happen if all the objects are missing supported signatures.
		return results, nil
	}
	keysFromDatabase, err := k.KeyDatabase.FetchKeys(ctx, keyRequests)
	if err != nil {
		return nil, err
	}

	keysFetched := map[PublicKeyLookupRequest]PublicKeyLookupResult{}
	now := AsTimestamp(time.Now())
	for req, res := range keysFromDatabase {
		if res.ExpiredTS != PublicKeyNotExpired {
			// The key is expired - it's not going to change so just return
			// it and don't bother requesting it again.
			keysFetched[req] = res
			delete(keyRequests, req)
			continue
		}
		// The key isn't expired so include it in the results.
		keysFetched[req] = res
		// If the key is inside validity then we don't need to update it.
		if now < res.ValidUntilTS && res.ExpiredTS == PublicKeyNotExpired {
			delete(keyRequests, req)
		}
	}

	if len(keysFetched) == numRequests {
		// If our key requests are all satisfied then we can try performing
		// a verification using our keys.
		k.checkUsingKeys(requests, results, keyIDs, keysFetched)

		// If we run into any errors when verifying using the keys that we
		// have then we can hit federation and check for updated keys.
		errored := false
		for _, r := range results {
			if r.Error != nil {
				errored = true
				break
			}
		}
		if !errored {
			return results, nil
		}
	}

	for _, fetcher := range k.KeyFetchers {
		// If we have all of the keys that we need now then we can
		// break the loop.
		if len(keyRequests) == 0 {
			break
		}

		fetcherLogger := logger.WithField("fetcher", fetcher.FetcherName())

		// TODO: Coalesce in-flight requests for the same keys.
		// Otherwise we risk spamming the servers we query the keys from.

		fetcherLogger.WithField("num_key_requests", len(keyRequests)).
			Info("Requesting keys from fetcher")

		fetched, err := fetcher.FetchKeys(ctx, keyRequests)
		if err != nil {
			fetcherLogger.WithError(err).Warn("Failed to request keys from fetcher")
			continue
		}

		if len(fetched) == 0 {
			fetcherLogger.Warn("Failed to retrieve any keys")
			continue
		}

		fetcherLogger.WithField("num_keys_fetched", len(fetched)).
			Info("Got keys from fetcher")

		// Hold the new keys and remove them from the request queue.
		for req, res := range fetched {
			keysFetched[req] = res
			delete(keyRequests, req)
		}
	}

	// Now that we've fetched all of the keys we need, try to check
	// if the requests are valid.
	k.checkUsingKeys(requests, results, keyIDs, keysFetched)

	// Add the keys to the database so that we won't need to fetch them again.
	if err := k.KeyDatabase.StoreKeys(ctx, keysFetched); err != nil {
		return nil, err
	}

	return results, nil
}

func (k *KeyRing) isAlgorithmSupported(keyID KeyID) bool {
	return strings.HasPrefix(string(keyID), "ed25519:")
}

func (k *KeyRing) publicKeyRequests(
	requests []VerifyJSONRequest, results []VerifyJSONResult, keyIDs [][]KeyID,
) map[PublicKeyLookupRequest]Timestamp {
	keyRequests := map[PublicKeyLookupRequest]Timestamp{}
	for i := range requests {
		if results[i].Error == nil {
			// We've already verified this message, we don't need to refetch the keys for it.
			continue
		}
		for _, keyID := range keyIDs[i] {
			k := PublicKeyLookupRequest{requests[i].ServerName, keyID}
			// Grab the maximum neeeded TS for this server and key ID.
			// This will default to 0 if the server and keyID weren't in the map.
			maxTS := keyRequests[k]
			if maxTS <= requests[i].AtTS {
				// We clobber on equality since that means that if the server and keyID
				// weren't already in the map and since AtTS is unsigned and since the
				// default value for maxTS is 0 we will always insert an entry for the
				// server and keyID.
				keyRequests[k] = requests[i].AtTS
			}
		}
	}
	return keyRequests
}

func (k *KeyRing) checkUsingKeys(
	requests []VerifyJSONRequest, results []VerifyJSONResult, keyIDs [][]KeyID,
	keys map[PublicKeyLookupRequest]PublicKeyLookupResult,
) {
	procs := runtime.NumCPU() - 1
	if procs < 1 {
		procs = 1
	}
	type job struct {
		index   int               // the original index in the requests/results array
		request VerifyJSONRequest // the request itself
	}
	jobs := make(map[int][]job)
	for i := range requests {
		jobs[i%procs] = append(jobs[i%procs], job{i, requests[i]})
	}
	var wg sync.WaitGroup // tracks the workers
	var mu sync.RWMutex   // protects results array
	wg.Add(len(jobs))
	for _, j := range jobs {
		go func(jobs []job) {
			for _, j := range jobs {
				mu.RLock()
				if results[j.index].Error == nil {
					// We've already checked this message and it passed the signature checks.
					// So we can skip to the next message.
					mu.RUnlock()
					continue
				}
				mu.RUnlock()
				for _, keyID := range keyIDs[j.index] {
					serverKey, ok := keys[PublicKeyLookupRequest{j.request.ServerName, keyID}]
					if !ok {
						// No key for this key ID so we continue onto the next key ID.
						continue
					}
					if !serverKey.WasValidAt(j.request.AtTS, j.request.StrictValidityChecking) {
						// The key wasn't valid at the timestamp we needed it to be valid at.
						// So skip onto the next key.
						mu.Lock()
						results[j.index].Error = fmt.Errorf(
							"gomatrixserverlib: key with ID %q for %q not valid at %d",
							keyID, j.request.ServerName, j.request.AtTS,
						)
						mu.Unlock()
						continue
					}
					if err := VerifyJSON(
						string(j.request.ServerName), keyID, ed25519.PublicKey(serverKey.Key), j.request.Message,
					); err != nil {
						// The signature wasn't valid, record the error and try the next key ID.
						mu.Lock()
						results[j.index].Error = err
						mu.Unlock()
						continue
					}
					// The signature is valid, set the result to nil.
					mu.Lock()
					results[j.index].Error = nil
					mu.Unlock()
					break
				}
			}
			wg.Done()
		}(j)
	}
	wg.Wait()
}

type KeyClient interface {
	GetServerKeys(ctx context.Context, matrixServer ServerName) (ServerKeys, error)
	LookupServerKeys(ctx context.Context, matrixServer ServerName, keyRequests map[PublicKeyLookupRequest]Timestamp) ([]ServerKeys, error)
}

// A PerspectiveKeyFetcher fetches server keys from a single perspective server.
type PerspectiveKeyFetcher struct {
	// The name of the perspective server to fetch keys from.
	PerspectiveServerName ServerName
	// The ed25519 public keys the perspective server must sign responses with.
	PerspectiveServerKeys map[KeyID]ed25519.PublicKey
	// The federation client to use to fetch keys with.
	Client KeyClient
}

// FetcherName implements KeyFetcher
func (p PerspectiveKeyFetcher) FetcherName() string {
	return fmt.Sprintf("perspective server %s", p.PerspectiveServerName)
}

// FetchKeys implements KeyFetcher
func (p *PerspectiveKeyFetcher) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	serverKeys, err := p.Client.LookupServerKeys(ctx, p.PerspectiveServerName, requests)
	if err != nil {
		return nil, fmt.Errorf("gomatrixserverlib: unable to lookup server keys: %w", err)
	}

	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	for _, keys := range serverKeys {
		var valid bool
		keyIDs, err := ListKeyIDs(string(p.PerspectiveServerName), keys.Raw)
		if err != nil {
			// The response from the perspective server was corrupted.
			return nil, fmt.Errorf("gomatrixserverlib: unable to list key IDs: %w", err)
		}
		for _, keyID := range keyIDs {
			perspectiveKey, ok := p.PerspectiveServerKeys[keyID]
			if !ok {
				// We don't have a key for that keyID, skip to the next keyID.
				continue
			}
			if err := VerifyJSON(string(p.PerspectiveServerName), keyID, perspectiveKey, keys.Raw); err != nil {
				// An invalid signature is very bad since it means we have a
				// problem talking to the perspective server.
				return nil, fmt.Errorf("gomatrixserverlib: unable to verify response: %w", err)
			}
			valid = true
			break
		}
		if !valid {
			// This means we don't have a known signature from the perspective server.
			return nil, fmt.Errorf("gomatrixserverlib: not signed with a known key for the perspective server")
		}

		// Check that the keys are valid for the server they claim to be
		checks, _ := CheckKeys(keys.ServerName, time.Unix(0, 0), keys)
		if !checks.AllChecksOK {
			// This is bad because it means that the perspective server was trying to feed us an invalid response.
			return nil, fmt.Errorf("gomatrixserverlib: key response from perspective server failed checks")
		}

		// TODO (matrix-org/dendrite#345): What happens if the same key ID
		// appears in multiple responses?
		// We should probably take the response with the highest valid_until_ts.
		mapServerKeysToPublicKeyLookupResult(keys, results)
	}

	return results, nil
}

// A DirectKeyFetcher fetches keys directly from a server.
// This may be suitable for local deployments that are firewalled from the public internet where DNS can be trusted.
type DirectKeyFetcher struct {
	// The federation client to use to fetch keys with.
	Client KeyClient
}

// FetcherName implements KeyFetcher
func (d DirectKeyFetcher) FetcherName() string {
	return "DirectKeyFetcher"
}

// FetchKeys implements KeyFetcher
func (d *DirectKeyFetcher) FetchKeys(
	ctx context.Context, requests map[PublicKeyLookupRequest]Timestamp,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	fetcherLogger := util.GetLogger(ctx).WithField("fetcher", d.FetcherName())

	byServer := map[ServerName]map[PublicKeyLookupRequest]Timestamp{}
	for req, ts := range requests {
		server := byServer[req.ServerName]
		if server == nil {
			server = map[PublicKeyLookupRequest]Timestamp{}
			byServer[req.ServerName] = server
		}
		server[req] = ts
	}

	// Work out the number of workers that we want to start. If the
	// number of outstanding requests is less than the current max
	// then reduce it so we don't start workers unnecessarily.
	numWorkers := 64
	if len(byServer) < numWorkers {
		numWorkers = len(byServer)
	}

	// Prepare somewhere to put the results. This map is protected
	// by the below mutex.
	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}
	var resultsMutex sync.Mutex

	// Populate the wait group with the number of workers.
	var wait sync.WaitGroup
	wait.Add(numWorkers)

	// Populate the jobs queue.
	pending := make(chan ServerName, len(byServer))
	for serverName := range byServer {
		pending <- serverName
	}
	close(pending)

	// Define our worker.
	worker := func(ch <-chan ServerName) {
		defer wait.Done()
		for server := range ch {
			serverResults, err := d.fetchKeysForServer(ctx, server)
			if err != nil {
				serverResults, err = d.fetchNotaryKeysForServer(ctx, server)
				if err != nil {
					// TODO: Should we actually be erroring here? or should we just drop those keys from the result map?
					fetcherLogger.WithError(err).Error("Failed to fetch key for server")
					continue
				}
			}
			resultsMutex.Lock()
			for req, keys := range serverResults {
				results[req] = keys
			}
			resultsMutex.Unlock()
		}
	}

	// Start the workers.
	for i := 0; i < numWorkers; i++ {
		go worker(pending)
	}

	// Wait for the workers to finish before returning
	// the results.
	wait.Wait()
	return results, nil
}

func (d *DirectKeyFetcher) fetchKeysForServer(
	ctx context.Context, serverName ServerName,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()

	keys, err := d.Client.GetServerKeys(ctx, serverName)
	if err != nil {
		if err != nil {
			return nil, err
		}
	}
	// Check that the keys are valid for the server.
	checks, _ := CheckKeys(serverName, time.Unix(0, 0), keys)
	if !checks.AllChecksOK {
		return nil, fmt.Errorf("gomatrixserverlib: key response direct from %q failed checks", serverName)
	}

	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	// TODO (matrix-org/dendrite#345): What happens if the same key ID
	// appears in multiple responses? We should probably reject the response.
	mapServerKeysToPublicKeyLookupResult(keys, results)

	return results, nil
}

func (d *DirectKeyFetcher) fetchNotaryKeysForServer(
	ctx context.Context, serverName ServerName,
) (map[PublicKeyLookupRequest]PublicKeyLookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*15)
	defer cancel()

	var keys ServerKeys
	allKeys, err := d.Client.LookupServerKeys(ctx, serverName, map[PublicKeyLookupRequest]Timestamp{
		{serverName, ""}: AsTimestamp(time.Now()),
	})
	if err != nil {
		return nil, err
	}
	found := false
	for _, serverKeys := range allKeys {
		if serverKeys.ServerName == serverName {
			keys = serverKeys
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("gomatrixserverlib: notary key response contained no results for %q", serverName)
	}
	// Check that the keys are valid for the server.
	checks, _ := CheckKeys(serverName, time.Unix(0, 0), keys)
	if !checks.AllChecksOK {
		return nil, fmt.Errorf("gomatrixserverlib: notary key response direct from %q failed checks", serverName)
	}

	results := map[PublicKeyLookupRequest]PublicKeyLookupResult{}

	// TODO (matrix-org/dendrite#345): What happens if the same key ID
	// appears in multiple responses? We should probably reject the response.
	mapServerKeysToPublicKeyLookupResult(keys, results)

	return results, nil
}

// mapServerKeysToPublicKeyLookupResult takes the (verified) result from a
// /key/v2/query call and inserts it into a PublicKeyLookupRequest->PublicKeyLookupResult
// map.
func mapServerKeysToPublicKeyLookupResult(serverKeys ServerKeys, results map[PublicKeyLookupRequest]PublicKeyLookupResult) {
	for keyID, key := range serverKeys.VerifyKeys {
		results[PublicKeyLookupRequest{
			ServerName: serverKeys.ServerName,
			KeyID:      keyID,
		}] = PublicKeyLookupResult{
			VerifyKey:    key,
			ValidUntilTS: serverKeys.ValidUntilTS,
			ExpiredTS:    PublicKeyNotExpired,
		}
	}
	for keyID, key := range serverKeys.OldVerifyKeys {
		results[PublicKeyLookupRequest{
			ServerName: serverKeys.ServerName,
			KeyID:      keyID,
		}] = PublicKeyLookupResult{
			VerifyKey:    key.VerifyKey,
			ValidUntilTS: PublicKeyNotValid,
			ExpiredTS:    key.ExpiredTS,
		}
	}
}
