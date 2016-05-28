// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
	"golang.org/x/net/context"
)

// CanonicalTlfName is a string containing the canonical name of a TLF.
type CanonicalTlfName string

type resolutionInfo struct {
	assertion string
	name      libkb.NormalizedUsername
	uid       keybase1.UID
}

// TlfHandle contains all the info in a BareTlfHandle as well as
// additional info. This doesn't embed BareTlfHandle to avoid having
// to keep track of data in multiple places.
type TlfHandle struct {
	// If this is true, resolvedReaders and unresolvedReaders
	// should both be nil.
	public          bool
	resolvedWriters map[string]resolutionInfo
	resolvedReaders map[string]resolutionInfo
	// Both unresolvedWriters and unresolvedReaders are stored in
	// sorted order.
	unresolvedWriters []keybase1.SocialAssertion
	unresolvedReaders []keybase1.SocialAssertion
	conflictInfo      *ConflictInfo
	// name can be computed from the other fields, but is cached
	// for speed.
	name CanonicalTlfName
}

// IsPublic returns whether or not this TlfHandle represents a public
// top-level folder.
func (h TlfHandle) IsPublic() bool {
	return h.public
}

// IsWriter returns whether or not the given user is a writer for the
// top-level folder represented by this TlfHandle.
func (h TlfHandle) IsWriter(user keybase1.UID) bool {
	for _, resInfo := range h.resolvedWriters {
		if resInfo.uid == user {
			return true
		}
	}
	return false
}

// IsReader returns whether or not the given user is a reader for the
// top-level folder represented by this TlfHandle.
func (h TlfHandle) IsReader(user keybase1.UID) bool {
	if h.public || h.IsWriter(user) {
		return true
	}
	for _, resInfo := range h.resolvedReaders {
		if resInfo.uid == user {
			return true
		}
	}
	return false
}

func getResolvedUIDs(resInfos map[string]resolutionInfo) []keybase1.UID {
	if len(resInfos) == 0 {
		return nil
	}
	uidMap := make(map[keybase1.UID]bool, len(resInfos))
	uids := make([]keybase1.UID, 0, len(resInfos))
	for _, resInfo := range resInfos {
		_, ok := uidMap[resInfo.uid]
		if ok {
			continue
		}
		uidMap[resInfo.uid] = true
		uids = append(uids, resInfo.uid)
	}
	return uids
}

func (h TlfHandle) unsortedResolvedWriters() []keybase1.UID {
	return getResolvedUIDs(h.resolvedWriters)
}

// ResolvedWriters returns the handle's resolved writer UIDs in sorted
// order.
func (h TlfHandle) ResolvedWriters() []keybase1.UID {
	writers := h.unsortedResolvedWriters()
	sort.Sort(uidList(writers))
	return writers
}

// FirstResolvedWriter returns the handle's first resolved writer UID
// (when sorted). This is used mostly for tests.
func (h TlfHandle) FirstResolvedWriter() keybase1.UID {
	return h.ResolvedWriters()[0]
}

func (h TlfHandle) unsortedResolvedReaders() []keybase1.UID {
	return getResolvedUIDs(h.resolvedReaders)
}

// ResolvedReaders returns the handle's resolved reader UIDs in sorted
// order. If the handle is public, nil will be returned.
func (h TlfHandle) ResolvedReaders() []keybase1.UID {
	readers := h.unsortedResolvedReaders()
	sort.Sort(uidList(readers))
	return readers
}

func (h TlfHandle) GetNeededIdentifies() []resolutionInfo {
	var resInfos []resolutionInfo
	for _, w := range h.resolvedWriters {
		resInfos = append(resInfos, w)
	}
	for _, r := range h.resolvedReaders {
		resInfos = append(resInfos, r)
	}
	return resInfos
}

// UnresolvedWriters returns the handle's unresolved writers in sorted
// order.
func (h TlfHandle) UnresolvedWriters() []keybase1.SocialAssertion {
	if len(h.unresolvedWriters) == 0 {
		return nil
	}
	unresolvedWriters := make([]keybase1.SocialAssertion, len(h.unresolvedWriters))
	copy(unresolvedWriters, h.unresolvedWriters)
	return unresolvedWriters
}

// UnresolvedReaders returns the handle's unresolved readers in sorted
// order. If the handle is public, nil will be returned.
func (h TlfHandle) UnresolvedReaders() []keybase1.SocialAssertion {
	if len(h.unresolvedReaders) == 0 {
		return nil
	}
	unresolvedReaders := make([]keybase1.SocialAssertion, len(h.unresolvedReaders))
	copy(unresolvedReaders, h.unresolvedReaders)
	return unresolvedReaders
}

// ConflictInfo returns the handle's conflict info, if any.
func (h TlfHandle) ConflictInfo() *ConflictInfo {
	if h.conflictInfo == nil {
		return nil
	}
	conflictInfoCopy := *h.conflictInfo
	return &conflictInfoCopy
}

// SetConflictInfo sets the handle's conflict info to the given one,
// which may be nil.
func (h *TlfHandle) SetConflictInfo(info *ConflictInfo) {
	if info == nil {
		h.conflictInfo = nil
		return
	}
	conflictInfoCopy := *info
	h.conflictInfo = &conflictInfoCopy
}

// ToBareHandle returns a BareTlfHandle corresponding to this handle.
func (h TlfHandle) ToBareHandle() (BareTlfHandle, error) {
	var readers []keybase1.UID
	if h.public {
		readers = []keybase1.UID{keybase1.PUBLIC_UID}
	} else {
		readers = h.unsortedResolvedReaders()
	}
	return MakeBareTlfHandle(
		h.unsortedResolvedWriters(), readers,
		h.unresolvedWriters, h.unresolvedReaders,
		h.conflictInfo)
}

// ToBareHandleOrBust returns a BareTlfHandle corresponding to this
// handle, and panics if there's an error. Used by tests.
func (h TlfHandle) ToBareHandleOrBust() BareTlfHandle {
	bh, err := h.ToBareHandle()
	if err != nil {
		panic(err)
	}
	return bh
}

type resolvableUser interface {
	// resolve must do exactly one of the following:
	//
	//   - return a non-zero resolutionInfo;
	//   - return a non-zero keybase1.SocialAssertion;
	//   - return a non-nil error.
	resolve(context.Context) (resolutionInfo, keybase1.SocialAssertion, error)
}

func resolveOneUser(
	ctx context.Context, user resolvableUser,
	errCh chan<- error, resolutionInfoResults chan<- resolutionInfo,
	socialAssertionResults chan<- keybase1.SocialAssertion) {
	resInfo, socialAssertion, err := user.resolve(ctx)
	if err != nil {
		select {
		case errCh <- err:
		default:
			// another worker reported an error before us;
			// first one wins
		}
		return
	}
	if resInfo != (resolutionInfo{}) {
		resolutionInfoResults <- resInfo
		return
	}

	if socialAssertion != (keybase1.SocialAssertion{}) {
		socialAssertionResults <- socialAssertion
		return
	}

	errCh <- fmt.Errorf("Resolving %v resulted in empty resolutionInfo and empty socialAssertion", user)
}

func makeTlfHandleHelper(
	ctx context.Context, public bool, writers, readers []resolvableUser,
	conflictInfo *ConflictInfo) (*TlfHandle, error) {
	if public && len(readers) > 0 {
		return nil, errors.New("public folder cannot have readers")
	}

	// parallelize the resolutions for each user
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)

	wc := make(chan resolutionInfo, len(writers))
	uwc := make(chan keybase1.SocialAssertion, len(writers))
	for _, writer := range writers {
		go resolveOneUser(ctx, writer, errCh, wc, uwc)
	}

	rc := make(chan resolutionInfo, len(readers))
	urc := make(chan keybase1.SocialAssertion, len(readers))
	for _, reader := range readers {
		go resolveOneUser(ctx, reader, errCh, rc, urc)
	}

	resolvedWriters := make(map[string]resolutionInfo)
	resolvedReaders := make(map[string]resolutionInfo)
	usedWriterUIDs := make(map[keybase1.UID]bool)
	usedUnresolvedWriters := make(map[keybase1.SocialAssertion]bool)
	usedUnresolvedReaders := make(map[keybase1.SocialAssertion]bool)
	for i := 0; i < len(writers)+len(readers); i++ {
		select {
		case err := <-errCh:
			return nil, err
		case resInfo := <-wc:
			if _, ok := resolvedWriters[resInfo.assertion]; ok {
				return nil, fmt.Errorf("writer assertion %q appears multiple times", resInfo.assertion)
			}
			usedWriterUIDs[resInfo.uid] = true
			resolvedWriters[resInfo.assertion] = resInfo
		case resInfo := <-rc:
			if _, ok := resolvedReaders[resInfo.assertion]; ok {
				return nil, fmt.Errorf("reader assertion %q appears multiple times", resInfo.assertion)
			}
			resolvedReaders[resInfo.assertion] = resInfo
		case socialAssertion := <-uwc:
			usedUnresolvedWriters[socialAssertion] = true
		case socialAssertion := <-urc:
			usedUnresolvedReaders[socialAssertion] = true
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	for assertion := range resolvedWriters {
		delete(resolvedReaders, assertion)
	}

	for k, resInfo := range resolvedReaders {
		if usedWriterUIDs[resInfo.uid] {
			delete(resolvedReaders, k)
		}
	}

	for sa := range usedUnresolvedWriters {
		delete(usedUnresolvedReaders, sa)
	}

	unresolvedWriters := getSortedUnresolved(usedUnresolvedWriters)

	var unresolvedReaders []keybase1.SocialAssertion
	if !public {
		unresolvedReaders = getSortedUnresolved(usedUnresolvedReaders)
	}

	writerNames := getSortedNames(resolvedWriters, unresolvedWriters)
	canonicalName := strings.Join(writerNames, ",")
	if !public && len(resolvedReaders)+len(unresolvedReaders) > 0 {
		readerNames := getSortedNames(resolvedReaders, unresolvedReaders)
		canonicalName += ReaderSep + strings.Join(readerNames, ",")
	}
	if conflictInfo != nil {
		canonicalName += ConflictSuffixSep + conflictInfo.String()
	}

	var conflictInfoCopy *ConflictInfo
	if conflictInfo != nil {
		c := *conflictInfo
		conflictInfoCopy = &c
	}
	h := &TlfHandle{
		public:            public,
		resolvedWriters:   resolvedWriters,
		resolvedReaders:   resolvedReaders,
		unresolvedWriters: unresolvedWriters,
		unresolvedReaders: unresolvedReaders,
		conflictInfo:      conflictInfoCopy,
		name:              CanonicalTlfName(canonicalName),
	}

	return h, nil
}

type resolvableUID struct {
	nug normalizedUsernameGetter
	uid keybase1.UID
}

func (ruid resolvableUID) resolve(ctx context.Context) (resolutionInfo, keybase1.SocialAssertion, error) {
	name, err := ruid.nug.GetNormalizedUsername(ctx, ruid.uid)
	if err != nil {
		return resolutionInfo{}, keybase1.SocialAssertion{}, err
	}
	return resolutionInfo{
		assertion: fmt.Sprintf("uid:%s", ruid.uid),
		name:      name,
		uid:       ruid.uid,
	}, keybase1.SocialAssertion{}, nil
}

type resolvableSocialAssertion keybase1.SocialAssertion

func (rsa resolvableSocialAssertion) resolve(ctx context.Context) (resolutionInfo, keybase1.SocialAssertion, error) {
	return resolutionInfo{}, keybase1.SocialAssertion(rsa), nil
}

// MakeTlfHandle creates a TlfHandle from the given BareTlfHandle and
// the given normalizedUsernameGetter (which is usually a KBPKI).
func MakeTlfHandle(
	ctx context.Context, bareHandle BareTlfHandle,
	nug normalizedUsernameGetter) (*TlfHandle, error) {
	writers := make([]resolvableUser, 0, len(bareHandle.Writers)+len(bareHandle.UnresolvedWriters))
	for _, w := range bareHandle.Writers {
		writers = append(writers, resolvableUID{nug, w})
	}
	for _, uw := range bareHandle.UnresolvedWriters {
		writers = append(writers, resolvableSocialAssertion(uw))
	}

	var readers []resolvableUser
	if !bareHandle.IsPublic() {
		readers = make([]resolvableUser, 0, len(bareHandle.Readers)+len(bareHandle.UnresolvedReaders))
		for _, r := range bareHandle.Readers {
			readers = append(readers, resolvableUID{nug, r})
		}
		for _, ur := range bareHandle.UnresolvedReaders {
			readers = append(readers, resolvableSocialAssertion(ur))
		}
	}

	h, err := makeTlfHandleHelper(ctx, bareHandle.IsPublic(), writers, readers, bareHandle.ConflictInfo)
	if err != nil {
		return nil, err
	}

	newHandle, err := h.ToBareHandle()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(newHandle, bareHandle) {
		panic(fmt.Errorf("newHandle=%+v unexpectedly not equal to bareHandle=%+v", newHandle, bareHandle))
	}

	return h, nil
}

func (h *TlfHandle) deepCopy() *TlfHandle {
	hCopy := TlfHandle{
		public:            h.public,
		name:              h.name,
		unresolvedWriters: h.UnresolvedWriters(),
		unresolvedReaders: h.UnresolvedReaders(),
		conflictInfo:      h.ConflictInfo(),
	}

	hCopy.resolvedWriters = make(map[string]resolutionInfo, len(h.resolvedWriters))
	for k, v := range h.resolvedWriters {
		hCopy.resolvedWriters[k] = v
	}

	hCopy.resolvedReaders = make(map[string]resolutionInfo, len(h.resolvedReaders))
	for k, v := range h.resolvedReaders {
		hCopy.resolvedReaders[k] = v
	}

	return &hCopy
}

func getSortedNames(
	resInfos map[string]resolutionInfo,
	unresolved []keybase1.SocialAssertion) []string {
	namesMap := make(map[string]bool)
	var names []string
	for _, resInfo := range resInfos {
		s := resInfo.name.String()
		if namesMap[s] {
			continue
		}
		namesMap[s] = true
		names = append(names, s)
	}
	for _, sa := range unresolved {
		names = append(names, sa.String())
	}
	sort.Sort(sort.StringSlice(names))
	return names
}

// GetCanonicalName returns the canonical name of this TLF.
func (h *TlfHandle) GetCanonicalName() CanonicalTlfName {
	if h.name == "" {
		panic(fmt.Sprintf("TlfHandle %v with no name", h))
	}

	return h.name
}

func buildCanonicalPath(public bool, canonicalName CanonicalTlfName) string {
	var folderType string
	if public {
		folderType = "public"
	} else {
		folderType = "private"
	}
	// TODO: Handle windows paths?
	return fmt.Sprintf("/keybase/%s/%s", folderType, canonicalName)
}

// GetCanonicalPath returns the full canonical path of this TLF.
func (h *TlfHandle) GetCanonicalPath() string {
	return buildCanonicalPath(h.IsPublic(), h.GetCanonicalName())
}

// ToFavorite converts a TlfHandle into a Favorite, suitable for
// Favorites calls.
func (h *TlfHandle) ToFavorite() Favorite {
	return Favorite{
		Name:   string(h.GetCanonicalName()),
		Public: h.IsPublic(),
	}
}

// ToFavorite converts a TlfHandle into a Favorite, and sets internal
// state about whether the corresponding folder was just created or
// not.
func (h *TlfHandle) toFavorite(created bool) Favorite {
	f := h.ToFavorite()
	f.created = created
	return f
}

type resolvableResolutionInfo resolutionInfo

func (rp resolvableResolutionInfo) resolve(ctx context.Context) (resolutionInfo, keybase1.SocialAssertion, error) {
	return resolutionInfo(rp), keybase1.SocialAssertion{}, nil
}

// ResolveAgainForUser tries to resolve any unresolved assertions in
// the given handle and returns a new handle with the results. As an
// optimization, if h contains no unresolved assertions, it just
// returns itself.  If uid != keybase1.UID(""), it only allows
// assertions that resolve to uid.
func (h *TlfHandle) ResolveAgainForUser(ctx context.Context, resolver resolver,
	uid keybase1.UID) (*TlfHandle, error) {
	if len(h.unresolvedWriters)+len(h.unresolvedReaders) == 0 {
		return h, nil
	}

	writers := make([]resolvableUser, 0, len(h.resolvedWriters)+len(h.unresolvedWriters))
	for _, resInfo := range h.resolvedWriters {
		writers = append(writers, resolvableResolutionInfo(resInfo))
	}
	for _, uw := range h.unresolvedWriters {
		writers = append(writers, resolvableAssertion{resolver,
			uw.String(), uid})
	}

	var readers []resolvableUser
	if !h.IsPublic() {
		readers = make([]resolvableUser, 0, len(h.resolvedReaders)+len(h.unresolvedReaders))
		for _, resInfo := range h.resolvedReaders {
			readers = append(readers, resolvableResolutionInfo(resInfo))
		}
		for _, ur := range h.unresolvedReaders {
			readers = append(readers, resolvableAssertion{resolver,
				ur.String(), uid})
		}
	}

	newH, err := makeTlfHandleHelper(ctx, h.IsPublic(), writers, readers, h.ConflictInfo())
	if err != nil {
		return nil, err
	}

	return newH, nil
}

// ResolveAgain tries to resolve any unresolved assertions in the
// given handle and returns a new handle with the results. As an
// optimization, if h contains no unresolved assertions, it just
// returns itself.
func (h *TlfHandle) ResolveAgain(ctx context.Context, resolver resolver) (
	*TlfHandle, error) {
	return h.ResolveAgainForUser(ctx, resolver, keybase1.UID(""))
}

func getSortedUnresolved(unresolved map[keybase1.SocialAssertion]bool) []keybase1.SocialAssertion {
	var assertions []keybase1.SocialAssertion
	for sa := range unresolved {
		assertions = append(assertions, sa)
	}
	sort.Sort(socialAssertionList(assertions))
	return assertions
}

func splitAndNormalizeTLFName(name string, public bool) (
	writerNames, readerNames []string,
	conflictSuffix string, err error) {

	names := strings.SplitN(name, ConflictSuffixSep, 2)
	if len(names) > 2 {
		return nil, nil, "", BadTLFNameError{name}
	}
	if len(names) > 1 {
		conflictSuffix = names[1]
	}

	splitNames := strings.SplitN(names[0], ReaderSep, 3)
	if len(splitNames) > 2 {
		return nil, nil, "", BadTLFNameError{name}
	}
	writerNames = strings.Split(splitNames[0], ",")
	if len(splitNames) > 1 {
		readerNames = strings.Split(splitNames[1], ",")
	}

	hasPublic := len(readerNames) == 0

	if public && !hasPublic {
		// No public folder exists for this folder.
		return nil, nil, "", NoSuchNameError{Name: name}
	}

	normalizedName, err := normalizeNamesInTLF(writerNames, readerNames, conflictSuffix)
	if err != nil {
		return nil, nil, "", err
	}
	if normalizedName != name {
		return nil, nil, "", TlfNameNotCanonical{name, normalizedName}
	}

	return writerNames, readerNames, strings.ToLower(conflictSuffix), nil
}

// TODO: this function can likely be replaced with a call to
// AssertionParseAndOnly when CORE-2967 and CORE-2968 are fixed.
func normalizeAssertionOrName(s string) (string, error) {
	if libkb.CheckUsername.F(s) {
		return libkb.NewNormalizedUsername(s).String(), nil
	}

	// TODO: this fails for http and https right now (see CORE-2968).
	socialAssertion, isSocialAssertion := libkb.NormalizeSocialAssertion(s)
	if isSocialAssertion {
		return socialAssertion.String(), nil
	}

	if expr, err := libkb.AssertionParseAndOnly(s); err == nil {
		// If the expression only contains a single url, make sure
		// it's not a just considered a single keybase username.  If
		// it is, then some non-username slipped into the default
		// "keybase" case and should be considered an error.
		urls := expr.CollectUrls(nil)
		if len(urls) == 1 && urls[0].IsKeybase() {
			return "", NoSuchUserError{s}
		}

		// Normalize and return.  Ideally `AssertionParseAndOnly`
		// would normalize for us, but that doesn't work yet, so for
		// now we'll just lower-case.  This will incorrectly lower
		// case http/https/web assertions, as well as case-sensitive
		// social assertions in AND expressions.  TODO: see CORE-2967.
		return strings.ToLower(s), nil
	}

	return "", BadTLFNameError{s}
}

// normalizeNamesInTLF takes a split TLF name and, without doing any
// resolutions or identify calls, normalizes all elements of the
// name. It then returns the normalized name.
func normalizeNamesInTLF(writerNames, readerNames []string,
	conflictSuffix string) (string, error) {
	sortedWriterNames := make([]string, len(writerNames))
	var err error
	for i, w := range writerNames {
		sortedWriterNames[i], err = normalizeAssertionOrName(w)
		if err != nil {
			return "", err
		}
	}
	sort.Strings(sortedWriterNames)
	normalizedName := strings.Join(sortedWriterNames, ",")
	if len(readerNames) > 0 {
		sortedReaderNames := make([]string, len(readerNames))
		for i, r := range readerNames {
			sortedReaderNames[i], err = normalizeAssertionOrName(r)
			if err != nil {
				return "", err
			}
		}
		sort.Strings(sortedReaderNames)
		normalizedName += ReaderSep + strings.Join(sortedReaderNames, ",")
	}
	if len(conflictSuffix) != 0 {
		// This *should* be normalized already but make sure.  I can see not
		// doing so might surprise a caller.
		normalizedName += ConflictSuffixSep + strings.ToLower(conflictSuffix)
	}

	return normalizedName, nil
}

type resolvableAssertion struct {
	resolver   resolver
	assertion  string
	mustBeUser keybase1.UID
}

func (ra resolvableAssertion) resolve(ctx context.Context) (
	resolutionInfo, keybase1.SocialAssertion, error) {
	if ra.assertion == PublicUIDName {
		return resolutionInfo{}, keybase1.SocialAssertion{}, fmt.Errorf("Invalid name %s", ra.assertion)
	}
	name, uid, err := ra.resolver.Resolve(ctx, ra.assertion)
	if err == nil && ra.mustBeUser != keybase1.UID("") && ra.mustBeUser != uid {
		// Force an unresolved assertion sinced the forced user doesn't match
		err = NoSuchUserError{ra.assertion}
	}
	switch err := err.(type) {
	default:
		return resolutionInfo{}, keybase1.SocialAssertion{}, err
	case nil:
		return resolutionInfo{
			assertion: ra.assertion,
			name:      name,
			uid:       uid,
		}, keybase1.SocialAssertion{}, nil
	case NoSuchUserError:
		socialAssertion, ok := libkb.NormalizeSocialAssertion(ra.assertion)
		if !ok {
			return resolutionInfo{}, keybase1.SocialAssertion{}, err
		}
		return resolutionInfo{}, socialAssertion, nil
	}
}

// ParseTlfHandle parses a TlfHandle from an encoded string. See
// TlfHandle.GetCanonicalName() for the opposite direction.
//
// Some errors that may be returned and can be specially handled:
//
// TlfNameNotCanonical: Returned when the given name is not canonical
// -- another name to try (which itself may not be canonical) is in
// the error. Usually, you want to treat this as a symlink to the name
// to try.
//
// NoSuchNameError: Returned when public is set and the given folder
// has no public folder.
func ParseTlfHandle(
	ctx context.Context, kbpki KBPKI, name string, public bool) (
	*TlfHandle, error) {
	// Before parsing the tlf handle (which results in identify
	// calls that cause tracker popups), first see if there's any
	// quick normalization of usernames we can do.  For example,
	// this avoids an identify in the case of "HEAD" which might
	// just be a shell trying to look for a git repo rather than a
	// real user lookup for "head" (KBFS-531).  Note that the name
	// might still contain assertions, which will result in
	// another alias in a subsequent lookup.
	writerNames, readerNames, conflictSuffix, err := splitAndNormalizeTLFName(name, public)
	if err != nil {
		return nil, err
	}

	hasPublic := len(readerNames) == 0

	if public && !hasPublic {
		// No public folder exists for this folder.
		return nil, NoSuchNameError{Name: name}
	}

	normalizedName, err := normalizeNamesInTLF(writerNames, readerNames, conflictSuffix)
	if err != nil {
		return nil, err
	}
	if normalizedName != name {
		return nil, TlfNameNotCanonical{name, normalizedName}
	}

	writers := make([]resolvableUser, len(writerNames))
	for i, w := range writerNames {
		writers[i] = resolvableAssertion{kbpki, w, keybase1.UID("")}
	}
	readers := make([]resolvableUser, len(readerNames))
	for i, r := range readerNames {
		readers[i] = resolvableAssertion{kbpki, r, keybase1.UID("")}
	}

	var conflictInfo *ConflictInfo
	if len(conflictSuffix) != 0 {
		conflictInfo, err = ParseConflictInfo(conflictSuffix)
		if err != nil {
			return nil, err
		}
	}

	h, err := makeTlfHandleHelper(ctx, public, writers, readers, conflictInfo)
	if err != nil {
		return nil, err
	}

	if !public {
		currentUsername, currentUID, err := kbpki.GetCurrentUserInfo(ctx)
		if err != nil {
			return nil, err
		}

		if !h.IsReader(currentUID) {
			return nil, ReadAccessError{currentUsername, h.GetCanonicalName(), public}
		}
	}

	if string(h.GetCanonicalName()) == name {
		// Name is already canonical (i.e., all usernames and
		// no assertions) so we can delay the identify until
		// the node is actually used.
		return h, nil
	}

	// Otherwise, identify before returning the canonical name.
	err = identifyHandle(ctx, kbpki, kbpki, h)
	if err != nil {
		return nil, err
	}

	return nil, TlfNameNotCanonical{name, string(h.GetCanonicalName())}
}

// CheckTlfHandleOffline does light checks whether a TLF handle looks ok,
// it avoids all network calls.
func CheckTlfHandleOffline(
	ctx context.Context, name string, public bool) error {
	_, _, _, err := splitAndNormalizeTLFName(name, public)
	return err
}
