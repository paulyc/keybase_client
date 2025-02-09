// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"fmt"
	"sync"
	"time"

	"github.com/keybase/client/go/kbfs/data"
	"github.com/keybase/client/go/kbfs/env"
	"github.com/keybase/client/go/kbfs/favorites"
	"github.com/keybase/client/go/kbfs/idutil"
	"github.com/keybase/client/go/kbfs/kbfscrypto"
	"github.com/keybase/client/go/kbfs/kbfsedits"
	"github.com/keybase/client/go/kbfs/kbfsmd"
	"github.com/keybase/client/go/kbfs/kbfssync"
	"github.com/keybase/client/go/kbfs/tlf"
	"github.com/keybase/client/go/kbfs/tlfhandle"
	"github.com/keybase/client/go/logger"
	"github.com/keybase/client/go/protocol/chat1"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

const (
	quotaUsageStaleTolerance = 10 * time.Second
)

// KBFSOpsStandard implements the KBFSOps interface, and is go-routine
// safe by forwarding requests to individual per-folder-branch
// handlers that are go-routine-safe.
type KBFSOpsStandard struct {
	appStateUpdater env.AppStateUpdater
	config          Config
	log             logger.Logger
	deferLog        logger.Logger
	ops             map[data.FolderBranch]*folderBranchOps
	opsByFav        map[favorites.Folder]*folderBranchOps
	opsLock         sync.RWMutex
	// reIdentifyControlChan controls reidentification.
	// Sending a value to this channel forces all fbos
	// to be marked for revalidation.
	// Closing this channel will shutdown the reidentification
	// watcher.
	reIdentifyControlChan chan chan<- struct{}

	favs *Favorites

	editActivity kbfssync.RepeatedWaitGroup
	editLock     sync.Mutex
	editShutdown bool

	currentStatus            *kbfsCurrentStatus
	quotaUsage               *EventuallyConsistentQuotaUsage
	longOperationDebugDumper *ImpatientDebugDumper
}

var _ KBFSOps = (*KBFSOpsStandard)(nil)

const longOperationDebugDumpDuration = time.Minute

// NewKBFSOpsStandard constructs a new KBFSOpsStandard object.
func NewKBFSOpsStandard(appStateUpdater env.AppStateUpdater, config Config) *KBFSOpsStandard {
	log := config.MakeLogger("")
	quLog := config.MakeLogger(QuotaUsageLogModule("KBFSOps"))
	kops := &KBFSOpsStandard{
		appStateUpdater:       appStateUpdater,
		config:                config,
		log:                   log,
		deferLog:              log.CloneWithAddedDepth(1),
		ops:                   make(map[data.FolderBranch]*folderBranchOps),
		opsByFav:              make(map[favorites.Folder]*folderBranchOps),
		reIdentifyControlChan: make(chan chan<- struct{}),
		favs:                  NewFavorites(config),
		quotaUsage: NewEventuallyConsistentQuotaUsage(
			config, quLog, config.MakeVLogger(quLog)),
		longOperationDebugDumper: NewImpatientDebugDumper(
			config, longOperationDebugDumpDuration),
		currentStatus: &kbfsCurrentStatus{},
	}
	kops.currentStatus.Init()
	go kops.markForReIdentifyIfNeededLoop()
	return kops
}

func (fs *KBFSOpsStandard) markForReIdentifyIfNeededLoop() {
	maxValid := fs.config.TLFValidDuration()
	// Tests and some users fail to set this properly.
	if maxValid <= 10*time.Second || maxValid > 24*365*time.Hour {
		maxValid = tlfValidDurationDefault
	}
	// Tick ten times the rate of valid duration allowing only overflows of +-10%
	ticker := time.NewTicker(maxValid / 10)
	for {
		var now time.Time
		var returnCh chan<- struct{}
		var ok bool
		select {
		// Normal case: feed the current time from config and mark fbos needing
		// validation.
		case <-ticker.C:
			now = fs.config.Clock().Now()
		// Mark everything for reidentification via now being the empty value or
		// quit.
		case returnCh, ok = <-fs.reIdentifyControlChan:
			if !ok {
				ticker.Stop()
				return
			}
		}
		fs.markForReIdentifyIfNeeded(now, maxValid)
		if returnCh != nil {
			returnCh <- struct{}{}
		}
	}
}

func (fs *KBFSOpsStandard) markForReIdentifyIfNeeded(
	now time.Time, maxValid time.Duration) {
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()

	for _, fbo := range fs.ops {
		fbo.markForReIdentifyIfNeeded(now, maxValid)
	}
}

func (fs *KBFSOpsStandard) shutdownEdits(ctx context.Context) error {
	fs.editLock.Lock()
	fs.editShutdown = true
	fs.editLock.Unlock()

	err := fs.editActivity.Wait(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Shutdown safely shuts down any background goroutines that may have
// been launched by KBFSOpsStandard.
func (fs *KBFSOpsStandard) Shutdown(ctx context.Context) error {
	defer fs.longOperationDebugDumper.Shutdown() // shut it down last
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	err := fs.shutdownEdits(ctx)
	if err != nil {
		return err
	}

	close(fs.reIdentifyControlChan)
	var errors []error
	if err := fs.favs.Shutdown(); err != nil {
		errors = append(errors, err)
	}
	for _, ops := range fs.ops {
		if err := ops.Shutdown(ctx); err != nil {
			errors = append(errors, err)
			// Continue on and try to shut down the other FBOs.
		}
	}
	if len(errors) == 1 {
		return errors[0]
	} else if len(errors) > 1 {
		// Aggregate errors
		return fmt.Errorf("Multiple errors on shutdown: %v", errors)
	}
	return nil
}

// PushConnectionStatusChange pushes human readable connection status changes.
func (fs *KBFSOpsStandard) PushConnectionStatusChange(
	service string, newStatus error) {
	fs.currentStatus.PushConnectionStatusChange(service, newStatus)

	if fs.config.KeybaseService() == nil {
		return
	}

	switch service {
	case KeybaseServiceName, GregorServiceName:
	default:
		return
	}

	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()

	for _, fbo := range fs.ops {
		fbo.PushConnectionStatusChange(service, newStatus)
	}

	if newStatus == nil {
		fs.log.CDebugf(nil, "Asking for an edit re-init after reconnection")
		fs.editActivity.Add(1)
		go fs.initTlfsForEditHistories()
	}
}

// PushStatusChange forces a new status be fetched by status listeners.
func (fs *KBFSOpsStandard) PushStatusChange() {
	fs.currentStatus.PushStatusChange()

	fs.log.CDebugf(nil, "Asking for an edit re-init after status change")
	fs.editActivity.Add(1)
	go fs.initTlfsForEditHistories()
}

// ClearPrivateFolderMD implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) ClearPrivateFolderMD(ctx context.Context) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()

	// Block until all private folders have been reset.  TODO:
	// parallelize these, as they can block for a while waiting for
	// the lock.
	for _, fbo := range fs.ops {
		// This call is a no-op for public folders.
		fbo.ClearPrivateFolderMD(ctx)
	}
}

// ForceFastForward implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) ForceFastForward(ctx context.Context) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()

	fs.log.CDebugf(ctx, "Forcing fast-forwards for %d folders", len(fs.ops))
	for _, fbo := range fs.ops {
		fbo.ForceFastForward(ctx)
	}
}

// InvalidateNodeAndChildren implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) InvalidateNodeAndChildren(
	ctx context.Context, node Node) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, node)
	return ops.InvalidateNodeAndChildren(ctx, node)
}

// GetFavorites implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) GetFavorites(ctx context.Context) (
	[]favorites.Folder, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	favs, err := fs.favs.Get(ctx)
	if err != nil {
		return nil, err
	}

	// Add the conflict status for any folders in a conflict state to
	// the favorite struct.
	journalManager, err := GetJournalManager(fs.config)
	if err != nil {
		// Journaling not enabled.
		return favs, nil
	}
	_, cleared, err := journalManager.GetJournalsInConflict(ctx)
	if err != nil {
		return nil, err
	}

	for _, c := range cleared {
		favs = append(favs, favorites.Folder{
			Name: string(c.Name),
			Type: c.Type,
		})
	}
	return favs, nil
}

// GetFavoritesAll implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) GetFavoritesAll(ctx context.Context) (
	keybase1.FavoritesResult, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	favs, err := fs.favs.GetAll(ctx)
	if err != nil {
		return keybase1.FavoritesResult{}, err
	}

	tlfIDs := fs.config.GetAllSyncedTlfs()

	// If we have any synced TLFs, create a quick-index map for
	// favorites based on name+type.
	type mapKey struct {
		name string
		t    keybase1.FolderType
	}
	var indexedFavs map[mapKey]int
	if len(tlfIDs) > 0 {
		indexedFavs = make(map[mapKey]int, len(favs.FavoriteFolders))
		for i, fav := range favs.FavoriteFolders {
			indexedFavs[mapKey{fav.Name, fav.FolderType}] = i
		}
	}

	// Add the sync config mode to each favorite.
	for _, id := range tlfIDs {
		config, err := fs.GetSyncConfig(ctx, id)
		if err != nil {
			return keybase1.FavoritesResult{}, err
		}

		if config.Mode == keybase1.FolderSyncMode_DISABLED {
			panic(fmt.Sprintf(
				"Folder %s has sync unexpectedly disabled", id))
		}

		fb := data.FolderBranch{Tlf: id, Branch: data.MasterBranch}
		_, h, err := fs.GetRootNodeMetadata(ctx, fb)
		if err != nil {
			return keybase1.FavoritesResult{}, err
		}

		name := string(h.GetCanonicalName())
		i, ok := indexedFavs[mapKey{name, id.Type().FolderType()}]
		if ok {
			favs.FavoriteFolders[i].SyncConfig = &config
		}
	}
	for i, fav := range favs.FavoriteFolders {
		if fav.SyncConfig != nil {
			continue
		}
		favs.FavoriteFolders[i].SyncConfig = &keybase1.FolderSyncConfig{
			Mode: keybase1.FolderSyncMode_DISABLED,
		}
	}

	// Add the conflict status for any folders in a conflict state to
	// the favorite struct.
	journalManager, err := GetJournalManager(fs.config)
	if err != nil {
		// Journaling not enabled.
		return favs, nil
	}
	conflicts, cleared, err := journalManager.GetJournalsInConflict(ctx)
	if err != nil {
		return keybase1.FavoritesResult{}, err
	}

	if len(conflicts) == 0 && len(cleared) == 0 {
		return favs, nil
	}

	clearedMap := make(map[string][]keybase1.Path)
	for _, c := range cleared {
		cs := keybase1.NewConflictStateWithManualresolvinglocalview(
			keybase1.ConflictManualResolvingLocalView{
				ServerView: c.ServerViewPath,
			})
		favs.FavoriteFolders = append(favs.FavoriteFolders,
			keybase1.Folder{
				Name:          string(c.Name),
				FolderType:    c.Type.FolderType(),
				Private:       c.Type != tlf.Public,
				ResetMembers:  []keybase1.User{},
				ConflictState: &cs,
			})

		clearedMap[c.ServerViewPath.String()] = append(
			clearedMap[c.ServerViewPath.String()], c.LocalViewPath)
	}

	conflictMap := make(map[ConflictJournalRecord]tlf.ID, len(conflicts))
	for _, c := range conflicts {
		conflictMap[ConflictJournalRecord{Name: c.Name, Type: c.Type}] = c.ID
	}

	found := 0
	for i, f := range favs.FavoriteFolders {
		name := tlf.CanonicalName(f.Name)
		t := tlf.TypeFromFolderType(f.FolderType)
		c := ConflictJournalRecord{
			Name: name,
			Type: t,
		}

		// First check for any current automatically-resolving
		// conflicts, those take precedence in terms of the state we
		// return.
		tlfID, ok := conflictMap[c]
		if ok {
			fb := data.FolderBranch{Tlf: tlfID, Branch: data.MasterBranch}
			ops := fs.getOps(ctx, fb, FavoritesOpNoChange)
			s, err := ops.FolderConflictStatus(ctx)
			if err != nil {
				return keybase1.FavoritesResult{}, err
			}
			if s != keybase1.FolderConflictType_NONE {
				stk := s == keybase1.FolderConflictType_IN_CONFLICT_AND_STUCK
				conflictState :=
					keybase1.NewConflictStateWithAutomaticresolving(
						keybase1.ConflictAutomaticResolving{IsStuck: stk})
				favs.FavoriteFolders[i].ConflictState = &conflictState
				found++
			}
		} else {
			// Otherwise, check whether this favorite has any local
			// conflict views.
			p := tlfhandle.BuildProtocolPathForTlfName(t, name)

			localViews, ok := clearedMap[p.String()]
			if ok {
				cs := keybase1.NewConflictStateWithManualresolvingserverview(
					keybase1.ConflictManualResolvingServerView{
						LocalViews: localViews,
					})
				favs.FavoriteFolders[i].ConflictState = &cs
				found++
			}
		}

		if found == len(conflictMap)+len(clearedMap) {
			// Short-circuit the loop if we've already found all the conflicts.
			break
		}
	}

	return favs, nil
}

// RefreshCachedFavorites implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) RefreshCachedFavorites(ctx context.Context,
	mode FavoritesRefreshMode) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.favs.RefreshCache(ctx, mode)
}

// ClearCachedFavorites implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) ClearCachedFavorites(ctx context.Context) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.favs.ClearCache(ctx)
}

// AddFavorite implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) AddFavorite(ctx context.Context,
	fav favorites.Folder, data favorites.Data) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	kbpki := fs.config.KBPKI()
	_, err := kbpki.GetCurrentSession(ctx)
	isLoggedIn := err == nil

	if isLoggedIn {
		err := fs.favs.Add(ctx, favorites.ToAdd{
			Folder:  fav,
			Data:    data,
			Created: false,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// SetFavoritesHomeTLFInfo implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) SetFavoritesHomeTLFInfo(ctx context.Context,
	info homeTLFInfo) {
	fs.favs.setHomeTLFInfo(ctx, info)
}

func (fs *KBFSOpsStandard) getOpsByFav(fav favorites.Folder) *folderBranchOps {
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	return fs.opsByFav[fav]
}

// RefreshEditHistory implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) RefreshEditHistory(fav favorites.Folder) {
	fbo := fs.getOpsByFav(fav)
	if fbo != nil {
		fbo.refreshEditHistory()
	}
}

// DeleteFavorite implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) DeleteFavorite(ctx context.Context,
	fav favorites.Folder) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	kbpki := fs.config.KBPKI()
	_, err := kbpki.GetCurrentSession(ctx)
	isLoggedIn := err == nil

	// Let this ops remove itself, if we have one available.
	ops := fs.getOpsByFav(fav)
	if ops != nil {
		err := ops.doFavoritesOp(ctx, FavoritesOpRemove, nil)
		if _, ok := err.(OpsCantHandleFavorite); !ok {
			return err
		}
		// If the ops couldn't handle the delete, fall through to
		// going directly via Favorites.
	}

	if isLoggedIn {
		err := fs.favs.Delete(ctx, fav)
		if err != nil {
			return err
		}
	}

	// TODO: Shut down the running folderBranchOps, if one exists?
	// What about open file handles?

	return nil
}

func (fs *KBFSOpsStandard) getOpsNoAdd(
	ctx context.Context, fb data.FolderBranch) *folderBranchOps {
	if fb == (data.FolderBranch{}) {
		panic("zero FolderBranch in getOps")
	}

	fs.opsLock.RLock()
	if ops, ok := fs.ops[fb]; ok {
		fs.opsLock.RUnlock()
		return ops
	}

	fs.opsLock.RUnlock()
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	// look it up again in case someone else got the lock
	ops, ok := fs.ops[fb]
	if !ok {
		bType := standard
		if fb.Branch.IsArchived() {
			bType = archive
		} else if fb.Branch.IsLocalConflict() {
			bType = conflict
		}
		var quotaUsage *EventuallyConsistentQuotaUsage
		if fb.Tlf.Type() != tlf.SingleTeam {
			// If this is a non-team TLF, pass in a shared quota usage
			// object, since the status of each non-team TLF will show
			// the same quota usage. TODO: for team TLFs, we should
			// also pass in a shared instance (see
			// `ConfigLocal.quotaUsage`).
			quotaUsage = fs.quotaUsage
		}
		ops = newFolderBranchOps(
			ctx, fs.appStateUpdater, fs.config, fb, bType, quotaUsage,
			fs.currentStatus, fs.favs)
		fs.ops[fb] = ops
	}
	return ops
}

func (fs *KBFSOpsStandard) getOpsIfExists(
	ctx context.Context, fb data.FolderBranch) *folderBranchOps {
	if fb == (data.FolderBranch{}) {
		panic("zero FolderBranch in getOps")
	}

	fs.opsLock.RLock()
	defer fs.opsLock.RUnlock()
	return fs.ops[fb]
}

func (fs *KBFSOpsStandard) getOps(ctx context.Context,
	fb data.FolderBranch, fop FavoritesOp) *folderBranchOps {
	ops := fs.getOpsNoAdd(ctx, fb)
	if err := ops.doFavoritesOp(ctx, fop, nil); err != nil {
		// Failure to favorite shouldn't cause a failure.  Just log
		// and move on.
		fs.log.CDebugf(ctx, "Couldn't add favorite: %v", err)
	}
	return ops
}

func (fs *KBFSOpsStandard) getOpsByNode(ctx context.Context,
	node Node) *folderBranchOps {
	return fs.getOps(ctx, node.GetFolderBranch(), FavoritesOpAdd)
}

func (fs *KBFSOpsStandard) getOpsByHandle(ctx context.Context,
	handle *tlfhandle.Handle, fb data.FolderBranch, fop FavoritesOp) *folderBranchOps {
	ops := fs.getOpsNoAdd(ctx, fb)
	if err := ops.doFavoritesOp(ctx, fop, handle); err != nil {
		// Failure to favorite shouldn't cause a failure.  Just log
		// and move on.
		fs.log.CDebugf(ctx, "Couldn't add favorite: %v", err)
	}

	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	fav := handle.ToFavorite()
	_, ok := fs.opsByFav[fav]
	if ok {
		// Already added.
		return ops
	}

	// Track under its name, so we can later tell it to remove itself
	// from the favorites list.
	fs.opsByFav[fav] = ops
	ops.RegisterForChanges(&kbfsOpsFavoriteObserver{
		kbfsOps: fs,
		currFav: fav,
	})
	return ops
}

func (fs *KBFSOpsStandard) resetTlfID(ctx context.Context, h *tlfhandle.Handle) error {
	if !h.IsBackedByTeam() {
		return errors.WithStack(NonExistentTeamForHandleError{h})
	}

	teamID, err := h.FirstResolvedWriter().AsTeam()
	if err != nil {
		return err
	}

	matches, epoch, err := h.TlfID().GetEpochFromTeamTLF(teamID)
	if err != nil {
		return err
	}
	if matches {
		epoch++
	} else {
		epoch = 0
	}

	// When creating a new TLF for an implicit team, always start with
	// epoch 0.  A different path will handle TLF resets with an
	// increased epoch, if necessary.
	tlfID, err := tlf.MakeIDFromTeam(h.Type(), teamID, epoch)
	if err != nil {
		return err
	}

	fs.log.CDebugf(ctx, "Creating new TLF ID %s for team %s, %s",
		tlfID, teamID, h.GetCanonicalName())

	err = fs.config.KBPKI().CreateTeamTLF(ctx, teamID, tlfID)
	if err != nil {
		return err
	}

	h.SetTlfID(tlfID)
	return fs.config.MDCache().PutIDForHandle(h, tlfID)
}

// createAndStoreTlfIDIfNeeded creates a TLF ID for a team-backed
// handle that doesn't have one yet, and associates it in the service
// with the team.  If it returns a `nil` error, it may have modified
// `h` to include the new TLF ID.
func (fs *KBFSOpsStandard) createAndStoreTlfIDIfNeeded(
	ctx context.Context, h *tlfhandle.Handle) error {
	if h.TlfID() != tlf.NullID {
		return nil
	}

	return fs.resetTlfID(ctx, h)
}

func (fs *KBFSOpsStandard) transformReadError(
	ctx context.Context, h *tlfhandle.Handle, err error) error {
	if errors.Cause(err) != context.DeadlineExceeded {
		return err
	}
	if _, ok := errors.Cause(err).(OfflineUnsyncedError); ok {
		return err
	}

	if fs.config.IsSyncedTlf(h.TlfID()) {
		fs.log.CWarningf(ctx, "Got a read timeout on a synced TLF: %+v", err)
		return err
	}

	// For unsynced TLFs, return a specific error to let the system
	// know to show a sync recommendation.
	return errors.WithStack(OfflineUnsyncedError{h})
}

func (fs *KBFSOpsStandard) getOrInitializeNewMDMaster(ctx context.Context,
	mdops MDOps, h *tlfhandle.Handle, fb data.FolderBranch, create bool, fop FavoritesOp) (
	initialized bool, md ImmutableRootMetadata, id tlf.ID, err error) {
	defer func() {
		err = fs.transformReadError(ctx, h, err)
		if tlfhandle.GetExtendedIdentify(ctx).Behavior.AlwaysRunIdentify() &&
			!initialized && err == nil {
			kbpki := fs.config.KBPKI()
			// We are not running identify for existing TLFs in
			// KBFS. This makes sure if requested, identify runs even
			// for existing TLFs.
			err = tlfhandle.IdentifyHandle(ctx, kbpki, kbpki, fs.config, h)
		}
	}()

	err = fs.createAndStoreTlfIDIfNeeded(ctx, h)
	if err != nil {
		return false, ImmutableRootMetadata{}, tlf.NullID, err
	}

	if rev, isRevBranch := fb.Branch.RevisionIfSpecified(); isRevBranch {
		fs.log.CDebugf(ctx, "Getting archived revision %d for branch %s",
			rev, fb.Branch)

		// Make sure that rev hasn't been garbage-collected yet.
		rmd, err := fs.getMDByHandle(ctx, h, FavoritesOpNoChange)
		if err != nil {
			return false, ImmutableRootMetadata{}, tlf.NullID, err
		}
		if rmd != (ImmutableRootMetadata{}) && rmd.IsReadable() {
			// `rev` is still readable even if it matches
			// `rmd.data.LastGCRevision`, since the GC process just
			// removes the unref'd blocks in that revision; the actual
			// data represented by the revision is still readable.
			if rev < rmd.data.LastGCRevision {
				return false, ImmutableRootMetadata{}, tlf.NullID,
					RevGarbageCollectedError{rev, rmd.data.LastGCRevision}
			}
		}

		md, err = getSingleMD(
			ctx, fs.config, h.TlfID(), kbfsmd.NullBranchID, rev,
			kbfsmd.Merged, nil)
		// This will error if there's no corresponding MD, which is
		// what we want since that means the user input an incorrect
		// MD revision.
		if err != nil {
			return false, ImmutableRootMetadata{}, tlf.NullID, err
		}
		return false, md, h.TlfID(), nil
	}

	md, err = mdops.GetForTLF(ctx, h.TlfID(), nil)
	if err != nil {
		return false, ImmutableRootMetadata{}, tlf.NullID, err
	}
	if md != (ImmutableRootMetadata{}) {
		return false, md, h.TlfID(), nil
	}

	if !create {
		return false, ImmutableRootMetadata{}, h.TlfID(), nil
	}

	// Init new MD.
	fops := fs.getOpsByHandle(ctx, h, fb, fop)
	err = fops.SetInitialHeadToNew(ctx, h.TlfID(), h)
	// Someone else initialized the TLF out from under us, so we
	// didn't initialize it.
	_, alreadyExisted := errors.Cause(err).(RekeyConflictError)
	if err != nil && !alreadyExisted {
		return false, ImmutableRootMetadata{}, tlf.NullID, err
	}

	md, err = mdops.GetForTLF(ctx, h.TlfID(), nil)
	if err != nil {
		return false, ImmutableRootMetadata{}, tlf.NullID, err
	}

	return !alreadyExisted, md, h.TlfID(), err

}

func (fs *KBFSOpsStandard) getMDByHandle(ctx context.Context,
	tlfHandle *tlfhandle.Handle, fop FavoritesOp) (rmd ImmutableRootMetadata, err error) {
	fbo := fs.getOpsByFav(tlfHandle.ToFavorite())
	if fbo != nil {
		lState := makeFBOLockState()
		rmd, err = fbo.getMDForReadNeedIdentifyOnMaybeFirstAccess(ctx, lState)
		if err != nil {
			return ImmutableRootMetadata{}, err
		}
	}
	if rmd != (ImmutableRootMetadata{}) {
		return rmd, nil
	}

	err = fs.createAndStoreTlfIDIfNeeded(ctx, tlfHandle)
	if err != nil {
		return ImmutableRootMetadata{}, err
	}

	// Check for an unmerged MD first if necessary.
	if fs.config.Mode().UnmergedTLFsEnabled() {
		rmd, err = fs.config.MDOps().GetUnmergedForTLF(
			ctx, tlfHandle.TlfID(), kbfsmd.NullBranchID)
		if err != nil {
			return ImmutableRootMetadata{}, err
		}
	}

	fb := data.FolderBranch{Tlf: tlfHandle.TlfID(), Branch: data.MasterBranch}
	if rmd == (ImmutableRootMetadata{}) {
		if fop == FavoritesOpAdd {
			_, rmd, _, err = fs.getOrInitializeNewMDMaster(
				ctx, fs.config.MDOps(), tlfHandle, fb, true,
				FavoritesOpAddNewlyCreated)
		} else {
			_, rmd, _, err = fs.getOrInitializeNewMDMaster(
				ctx, fs.config.MDOps(), tlfHandle, fb, true, fop)
		}
		if err != nil {
			return ImmutableRootMetadata{}, err
		}
	}

	// Make sure fbo exists and head is set so that next time we use this we
	// don't need to hit server even when there isn't any FS activity.
	if fbo == nil {
		fbo = fs.getOpsByHandle(ctx, tlfHandle, fb, fop)
	}
	if err = fbo.SetInitialHeadFromServer(ctx, rmd); err != nil {
		return ImmutableRootMetadata{}, err
	}

	return rmd, nil
}

// GetTLFCryptKeys implements the KBFSOps interface for
// KBFSOpsStandard
func (fs *KBFSOpsStandard) GetTLFCryptKeys(
	ctx context.Context, tlfHandle *tlfhandle.Handle) (
	keys []kbfscrypto.TLFCryptKey, id tlf.ID, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.log.CDebugf(ctx, "GetTLFCryptKeys(%s)", tlfHandle.GetCanonicalPath())
	defer func() { fs.deferLog.CDebugf(ctx, "Done: %+v", err) }()

	rmd, err := fs.getMDByHandle(ctx, tlfHandle, FavoritesOpNoChange)
	if err != nil {
		return nil, tlf.ID{}, err
	}
	keys, err = fs.config.KeyManager().GetTLFCryptKeyOfAllGenerations(ctx, rmd)
	return keys, rmd.TlfID(), err
}

// GetTLFID implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) GetTLFID(ctx context.Context,
	tlfHandle *tlfhandle.Handle) (id tlf.ID, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.log.CDebugf(ctx, "GetTLFID(%s)", tlfHandle.GetCanonicalPath())
	defer func() { fs.deferLog.CDebugf(ctx, "Done: %+v", err) }()

	rmd, err := fs.getMDByHandle(ctx, tlfHandle, FavoritesOpNoChange)
	if err != nil {
		return tlf.ID{}, err
	}
	return rmd.TlfID(), err
}

// GetTLFHandle implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) GetTLFHandle(ctx context.Context, node Node) (
	*tlfhandle.Handle, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, node)
	return ops.GetTLFHandle(ctx, node)
}

// getMaybeCreateRootNode is called for GetOrCreateRootNode and GetRootNode.
func (fs *KBFSOpsStandard) getMaybeCreateRootNode(
	ctx context.Context, h *tlfhandle.Handle, branch data.BranchName, create bool) (
	node Node, ei data.EntryInfo, err error) {
	fs.log.CDebugf(ctx, "getMaybeCreateRootNode(%s, %v, %v)",
		h.GetCanonicalPath(), branch, create)
	defer func() {
		err = fs.transformReadError(ctx, h, err)
		fs.deferLog.CDebugf(ctx, "Done: %+v", err)
	}()

	if branch != data.MasterBranch && create {
		return nil, data.EntryInfo{}, errors.Errorf(
			"Can't create a root node for branch %s", branch)
	}

	err = fs.createAndStoreTlfIDIfNeeded(ctx, h)
	if err != nil {
		return nil, data.EntryInfo{}, err
	}

	// Check if we already have the MD cached, before contacting any
	// servers.
	if h.TlfID() == tlf.NullID {
		return nil, data.EntryInfo{},
			errors.Errorf("Handle for %s doesn't have a TLF ID set",
				h.GetCanonicalPath())
	}
	fb := data.FolderBranch{Tlf: h.TlfID(), Branch: branch}
	fops := fs.getOpsIfExists(ctx, fb)
	if fops != nil {
		// If a folderBranchOps has already been initialized for this TLF,
		// use it to get the root node.  But if we haven't done an
		// identify yet, we better do so, because `getRootNode()` doesn't
		// do one.
		lState := makeFBOLockState()
		md, err := fops.getMDForReadNeedIdentifyOnMaybeFirstAccess(ctx, lState)
		if err != nil {
			return nil, data.EntryInfo{}, err
		}
		if md != (ImmutableRootMetadata{}) && md.IsReadable() {
			node, ei, _, err := fops.getRootNode(ctx)
			if err != nil {
				return nil, data.EntryInfo{}, err
			}
			if node != nil {
				return node, ei, nil
			}
		}
	}

	mdops := fs.config.MDOps()
	var md ImmutableRootMetadata
	// Check for an unmerged MD first if necessary.
	if fs.config.Mode().UnmergedTLFsEnabled() {
		md, err = mdops.GetUnmergedForTLF(ctx, h.TlfID(), kbfsmd.NullBranchID)
		if err != nil {
			return nil, data.EntryInfo{}, err
		}
	}

	if md == (ImmutableRootMetadata{}) {
		var id tlf.ID
		var initialized bool
		initialized, md, id, err = fs.getOrInitializeNewMDMaster(
			ctx, mdops, h, fb, create, FavoritesOpAdd)
		if err != nil {
			return nil, data.EntryInfo{}, err
		}
		if initialized {
			fb := data.FolderBranch{Tlf: id, Branch: data.MasterBranch}
			fops := fs.getOpsByHandle(ctx, h, fb, FavoritesOpAddNewlyCreated)

			node, ei, _, err = fops.getRootNode(ctx)
			if err != nil {
				return nil, data.EntryInfo{}, err
			}

			return node, ei, nil
		}
		if !create && md == (ImmutableRootMetadata{}) {
			kbpki := fs.config.KBPKI()
			err := tlfhandle.IdentifyHandle(ctx, kbpki, kbpki, fs.config, h)
			if err != nil {
				return nil, data.EntryInfo{}, err
			}
			fb := data.FolderBranch{Tlf: id, Branch: data.MasterBranch}
			fs.getOpsByHandle(ctx, h, fb, FavoritesOpAdd)
			return nil, data.EntryInfo{}, nil
		}
	}

	// we might not be able to read the metadata if we aren't in the
	// key group yet.
	if err := isReadableOrError(ctx, fs.config.KBPKI(), fs.config, md.ReadOnly()); err != nil {
		fs.opsLock.Lock()
		defer fs.opsLock.Unlock()
		// If we already have an FBO for this ID, trigger a rekey
		// prompt in the background, if possible.
		if ops, ok := fs.ops[fb]; ok {
			fs.log.CDebugf(ctx, "Triggering a paper prompt rekey on folder "+
				"access due to unreadable MD for %s", h.GetCanonicalPath())
			ops.rekeyFSM.Event(NewRekeyRequestWithPaperPromptEvent())
		}
		return nil, data.EntryInfo{}, err
	}

	ops := fs.getOpsByHandle(ctx, h, fb, FavoritesOpAdd)

	err = ops.SetInitialHeadFromServer(ctx, md)
	if err != nil {
		return nil, data.EntryInfo{}, err
	}

	node, ei, _, err = ops.getRootNode(ctx)
	if err != nil {
		return nil, data.EntryInfo{}, err
	}

	if err := ops.doFavoritesOp(ctx, FavoritesOpAdd, h); err != nil {
		// Failure to favorite shouldn't cause a failure.  Just log
		// and move on.
		fs.log.CDebugf(ctx, "Couldn't add favorite: %v", err)
	}
	return node, ei, nil
}

// GetOrCreateRootNode implements the KBFSOps interface for
// KBFSOpsStandard
func (fs *KBFSOpsStandard) GetOrCreateRootNode(
	ctx context.Context, h *tlfhandle.Handle, branch data.BranchName) (
	node Node, ei data.EntryInfo, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	return fs.getMaybeCreateRootNode(ctx, h, branch, true)
}

// GetRootNode implements the KBFSOps interface for
// KBFSOpsStandard. Returns a nil Node and nil error
// if the tlf does not exist but there is no error present.
func (fs *KBFSOpsStandard) GetRootNode(
	ctx context.Context, h *tlfhandle.Handle, branch data.BranchName) (
	node Node, ei data.EntryInfo, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	return fs.getMaybeCreateRootNode(ctx, h, branch, false)
}

// GetDirChildren implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) GetDirChildren(ctx context.Context, dir Node) (
	map[string]data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.GetDirChildren(ctx, dir)
}

// Lookup implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Lookup(ctx context.Context, dir Node, name string) (
	Node, data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.Lookup(ctx, dir, name)
}

// Stat implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Stat(ctx context.Context, node Node) (
	data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, node)
	return ops.Stat(ctx, node)
}

// CreateDir implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) CreateDir(
	ctx context.Context, dir Node, name string) (Node, data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.CreateDir(ctx, dir, name)
}

// CreateFile implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) CreateFile(
	ctx context.Context, dir Node, name string, isExec bool, excl Excl) (
	Node, data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.CreateFile(ctx, dir, name, isExec, excl)
}

// CreateLink implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) CreateLink(
	ctx context.Context, dir Node, fromName string, toPath string) (
	data.EntryInfo, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.CreateLink(ctx, dir, fromName, toPath)
}

// RemoveDir implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) RemoveDir(
	ctx context.Context, dir Node, name string) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.RemoveDir(ctx, dir, name)
}

// RemoveEntry implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) RemoveEntry(
	ctx context.Context, dir Node, name string) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, dir)
	return ops.RemoveEntry(ctx, dir, name)
}

// Rename implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Rename(
	ctx context.Context, oldParent Node, oldName string, newParent Node,
	newName string) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	oldFB := oldParent.GetFolderBranch()
	newFB := newParent.GetFolderBranch()

	// only works for nodes within the same topdir
	if oldFB != newFB {
		return RenameAcrossDirsError{}
	}

	ops := fs.getOpsByNode(ctx, oldParent)
	return ops.Rename(ctx, oldParent, oldName, newParent, newName)
}

// Read implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Read(
	ctx context.Context, file Node, dest []byte, off int64) (
	numRead int64, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, file)
	return ops.Read(ctx, file, dest, off)
}

// Write implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Write(
	ctx context.Context, file Node, data []byte, off int64) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, file)
	return ops.Write(ctx, file, data, off)
}

// Truncate implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Truncate(
	ctx context.Context, file Node, size uint64) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, file)
	return ops.Truncate(ctx, file, size)
}

// SetEx implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) SetEx(
	ctx context.Context, file Node, ex bool) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, file)
	return ops.SetEx(ctx, file, ex)
}

// SetMtime implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) SetMtime(
	ctx context.Context, file Node, mtime *time.Time) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, file)
	return ops.SetMtime(ctx, file, mtime)
}

// SyncAll implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) SyncAll(
	ctx context.Context, folderBranch data.FolderBranch) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpAdd)
	return ops.SyncAll(ctx, folderBranch)
}

// FolderStatus implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) FolderStatus(
	ctx context.Context, folderBranch data.FolderBranch) (
	FolderBranchStatus, <-chan StatusUpdate, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpNoChange)
	return ops.FolderStatus(ctx, folderBranch)
}

// FolderConflictStatus implements the KBFSOps interface for
// KBFSOpsStandard
func (fs *KBFSOpsStandard) FolderConflictStatus(
	ctx context.Context, folderBranch data.FolderBranch) (
	keybase1.FolderConflictType, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpNoChange)
	return ops.FolderConflictStatus(ctx)
}

// Status implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) Status(ctx context.Context) (
	KBFSStatus, <-chan StatusUpdate, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	session, err := fs.config.KBPKI().GetCurrentSession(ctx)
	var usageBytes, archiveBytes, limitBytes int64 = -1, -1, -1
	var gitUsageBytes, gitArchiveBytes, gitLimitBytes int64 = -1, -1, -1
	// Don't request the quota info until we're sure we've
	// authenticated with our password.  TODO: fix this in the
	// service/GUI by handling multiple simultaneous passphrase
	// requests at once.
	mdserver := fs.config.MDServer()
	switch errors.Cause(err).(type) {
	case nil:
		if mdserver != nil && mdserver.IsConnected() {
			var quErr error
			_, usageBytes, archiveBytes, limitBytes,
				gitUsageBytes, gitArchiveBytes, gitLimitBytes, quErr =
				fs.quotaUsage.GetAllTypes(
					ctx, quotaUsageStaleTolerance/2, quotaUsageStaleTolerance)
			if quErr != nil {
				// The error is ignored here so that other fields can still be populated
				// even if this fails.
				fs.log.CDebugf(ctx, "Getting quota usage error: %v", quErr)
			}
		} else {
			fs.log.CDebugf(ctx, "Skipping getting quota usage because "+
				"mdserver not set or not connected")
		}
	case idutil.NoCurrentSessionError:
		fs.log.CDebugf(ctx, "Skipping getting quota usage because "+
			"we are not logged in")
		err = nil
	default:
		return KBFSStatus{}, nil, err
	}

	failures, ch := fs.currentStatus.CurrentStatus()
	var jManagerStatus *JournalManagerStatus
	jManager, jErr := GetJournalManager(fs.config)
	if jErr == nil {
		status, tlfIDs := jManager.Status(ctx)
		jManagerStatus = &status
		err := FillInJournalStatusUnflushedPaths(
			ctx, fs.config, jManagerStatus, tlfIDs)
		if err != nil {
			// The caller might depend on the channel (e.g., in
			// libfs/remote_status.go), even in the case where err !=
			// nil.
			return KBFSStatus{}, ch, err
		}
		if usageBytes >= 0 {
			usageBytes += status.UnflushedBytes
		}
	}

	dbc := fs.config.DiskBlockCache()
	var dbcStatus map[string]DiskBlockCacheStatus
	if dbc != nil {
		dbcStatus = dbc.Status(ctx)
	}

	dmc := fs.config.DiskMDCache()
	var dmcStatus DiskMDCacheStatus
	if dmc != nil {
		dmcStatus = dmc.Status(ctx)
	}
	dqc := fs.config.DiskQuotaCache()
	var dqcStatus DiskQuotaCacheStatus
	if dqc != nil {
		dqcStatus = dqc.Status(ctx)
	}

	return KBFSStatus{
		CurrentUser:          session.Name.String(),
		IsConnected:          fs.config.MDServer().IsConnected(),
		UsageBytes:           usageBytes,
		ArchiveBytes:         archiveBytes,
		LimitBytes:           limitBytes,
		GitUsageBytes:        gitUsageBytes,
		GitArchiveBytes:      gitArchiveBytes,
		GitLimitBytes:        gitLimitBytes,
		FailingServices:      failures,
		JournalManager:       jManagerStatus,
		DiskBlockCacheStatus: dbcStatus,
		DiskMDCacheStatus:    dmcStatus,
		DiskQuotaCacheStatus: dqcStatus,
	}, ch, err
}

// UnstageForTesting implements the KBFSOps interface for KBFSOpsStandard
// TODO: remove once we have automatic conflict resolution
func (fs *KBFSOpsStandard) UnstageForTesting(
	ctx context.Context, folderBranch data.FolderBranch) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpAdd)
	return ops.UnstageForTesting(ctx, folderBranch)
}

// RequestRekey implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) RequestRekey(ctx context.Context, id tlf.ID) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	// We currently only support rekeys of master branches.
	ops := fs.getOps(ctx,
		data.FolderBranch{Tlf: id, Branch: data.MasterBranch}, FavoritesOpNoChange)
	ops.RequestRekey(ctx, id)
}

// SyncFromServer implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) SyncFromServer(ctx context.Context,
	folderBranch data.FolderBranch, lockBeforeGet *keybase1.LockID) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpAdd)
	return ops.SyncFromServer(ctx, folderBranch, lockBeforeGet)
}

// GetUpdateHistory implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) GetUpdateHistory(ctx context.Context,
	folderBranch data.FolderBranch) (history TLFUpdateHistory, err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpAdd)
	return ops.GetUpdateHistory(ctx, folderBranch)
}

// GetEditHistory implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) GetEditHistory(
	ctx context.Context, folderBranch data.FolderBranch) (
	tlfHistory keybase1.FSFolderEditHistory, err error) {
	ops := fs.getOps(ctx, folderBranch, FavoritesOpAdd)
	return ops.GetEditHistory(ctx, folderBranch)
}

// GetNodeMetadata implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) GetNodeMetadata(ctx context.Context, node Node) (
	NodeMetadata, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOpsByNode(ctx, node)
	return ops.GetNodeMetadata(ctx, node)
}

// GetRootNodeMetadata implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) GetRootNodeMetadata(
	ctx context.Context, folderBranch data.FolderBranch) (
	NodeMetadata, *tlfhandle.Handle, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx, folderBranch, FavoritesOpNoChange)
	rootNode, _, _, err := ops.getRootNode(ctx)
	if err != nil {
		return NodeMetadata{}, nil, err
	}
	md, err := ops.GetNodeMetadata(ctx, rootNode)
	if err != nil {
		return NodeMetadata{}, nil, err
	}

	h, err := ops.GetTLFHandle(ctx, rootNode)
	if err != nil {
		return NodeMetadata{}, nil, err
	}
	return md, h, nil
}

func (fs *KBFSOpsStandard) findTeamByID(
	ctx context.Context, tid keybase1.TeamID) *folderBranchOps {
	fs.opsLock.Lock()
	// Copy the ops list so we don't have to hold opsLock when calling
	// `getRootNode()` (which can lead to deadlocks).
	ops := make(map[data.FolderBranch]*folderBranchOps)
	for fb, fbo := range fs.ops {
		ops[fb] = fbo
	}
	fs.opsLock.Unlock()

	// We have to search for the tid since we don't know the old name
	// of the team here.  Should we add an index for this?
	for fb, fbo := range ops {
		_, _, handle, err := fbo.getRootNode(ctx)
		if err != nil {
			fs.log.CDebugf(
				ctx, "Error getting root node for %s: %+v", fb.Tlf, err)
			continue
		}

		if handle.TypeForKeying() != tlf.TeamKeying {
			continue
		}

		if handle.FirstResolvedWriter().AsTeamOrBust() != tid {
			continue
		}

		fs.log.CDebugf(ctx, "Team name changed for team %s", tid)
		return fbo
	}
	return nil
}

// TeamNameChanged implements the KBFSOps interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) TeamNameChanged(
	ctx context.Context, tid keybase1.TeamID) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.log.CDebugf(ctx, "Got TeamNameChanged for %s", tid)
	fbo := fs.findTeamByID(ctx, tid)
	if fbo != nil {
		go fbo.TeamNameChanged(ctx, tid)
	}
}

// TeamAbandoned implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) TeamAbandoned(
	ctx context.Context, tid keybase1.TeamID) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.log.CDebugf(ctx, "Got TeamAbandoned for %s", tid)
	fbo := fs.findTeamByID(ctx, tid)
	if fbo != nil {
		go fbo.TeamAbandoned(ctx, tid)
	}
}

// MigrateToImplicitTeam implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) MigrateToImplicitTeam(
	ctx context.Context, id tlf.ID) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	// We currently only migrate on the master branch of a TLF.
	ops := fs.getOps(ctx,
		data.FolderBranch{Tlf: id, Branch: data.MasterBranch}, FavoritesOpNoChange)
	return ops.MigrateToImplicitTeam(ctx, id)
}

// KickoffAllOutstandingRekeys implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) KickoffAllOutstandingRekeys() error {
	for _, op := range fs.ops {
		op.rekeyFSM.Event(newRekeyKickoffEvent())
	}
	return nil
}

func (fs *KBFSOpsStandard) initTLFWithoutIdentifyPopups(
	ctx context.Context, handle *tlfhandle.Handle) error {
	ctx, err := tlfhandle.MakeExtendedIdentify(
		ctx, keybase1.TLFIdentifyBehavior_KBFS_CHAT)
	if err != nil {
		return err
	}

	_, _, err = fs.getMaybeCreateRootNode(ctx, handle, data.MasterBranch, false)
	if err != nil {
		return err
	}

	// The popups and errors were suppressed, but any errors would
	// have been logged.  So just close out the extended identify.  If
	// the user accesses the TLF directly, another proper identify
	// should happen that shows errors.
	_ = tlfhandle.GetExtendedIdentify(ctx).GetTlfBreakAndClose()
	return nil
}

// NewNotificationChannel implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) NewNotificationChannel(
	ctx context.Context, handle *tlfhandle.Handle, convID chat1.ConversationID,
	channelName string) {
	if !fs.config.Mode().TLFEditHistoryEnabled() {
		return
	}

	fs.log.CDebugf(ctx, "New notification channel for %s",
		handle.GetCanonicalPath())

	// If the FBO already exists, notify it.  If the FBO doesn't exist
	// yet, we need to create it, so that it shows up in the edit
	// history.
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	fav := handle.ToFavorite()
	if ops, ok := fs.opsByFav[fav]; ok {
		ops.NewNotificationChannel(ctx, handle, convID, channelName)
	} else if handle.TlfID() != tlf.NullID {
		fs.editActivity.Add(1)
		go func() {
			defer fs.editActivity.Done()
			fs.log.CDebugf(ctx, "Initializing TLF %s for the edit history",
				handle.GetCanonicalPath())
			ctx := CtxWithRandomIDReplayable(
				context.Background(), CtxFBOIDKey, CtxFBOOpID, fs.log)
			// Fully initialize the TLF in order to kick off any
			// necessary prefetches.
			err := fs.initTLFWithoutIdentifyPopups(ctx, handle)
			if err != nil {
				fs.log.CDebugf(ctx, "Couldn't initialize TLF: %+v", err)
			}
		}()
	} else {
		fs.log.CWarningf(ctx,
			"Handle %s for existing folder unexpectedly has no TLF ID",
			handle.GetCanonicalName())
	}
	fs.favs.RefreshCacheWhenMTimeChanged(ctx)
}

// Reset implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) Reset(
	ctx context.Context, handle *tlfhandle.Handle) error {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	// First, make sure the folder has been reset according to the
	// mdserver.
	bareHandle, err := handle.ToBareHandle()
	if err != nil {
		return err
	}
	id, _, err := fs.config.MDServer().GetForHandle(
		ctx, bareHandle, kbfsmd.Merged, nil)
	if err == nil {
		fs.log.CDebugf(ctx, "Folder %s can't be reset; still has ID %s",
			handle.GetCanonicalPath(), id)
		return errors.WithStack(FolderNotResetOnServer{handle})
	} else if _, ok := errors.Cause(err).(kbfsmd.ServerErrorClassicTLFDoesNotExist); !ok {
		// Return errors if they don't indicate the folder is new.
		return err
	}

	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	fs.log.CDebugf(ctx, "Reset %s", handle.GetCanonicalPath())
	fb := data.FolderBranch{Tlf: handle.TlfID(), Branch: data.MasterBranch}
	ops, ok := fs.ops[fb]
	if ok {
		err := ops.Reset(ctx, handle)
		if err != nil {
			return err
		}
		delete(fs.ops, fb)
		fav := handle.ToFavorite()
		delete(fs.opsByFav, fav)
		err = ops.Shutdown(ctx)
		if err != nil {
			return err
		}
	}

	// Reset the TLF by overwriting the TLF ID in the sigchain.  This
	// assumes that the server is in implicit team mode for new TLFs,
	// which at this point it should always be.
	return fs.resetTlfID(ctx, handle)
}

// ClearConflictView resets a TLF's journal and conflict DB to a non
// -conflicting state.
func (fs *KBFSOpsStandard) ClearConflictView(ctx context.Context,
	tlfID tlf.ID) error {
	fbo := fs.getOpsNoAdd(ctx, data.FolderBranch{
		Tlf:    tlfID,
		Branch: data.MasterBranch,
	})
	return fbo.clearConflictView(ctx)
}

func (fs *KBFSOpsStandard) deleteOps(
	ctx context.Context, ops *folderBranchOps, fb data.FolderBranch) error {
	handle, err := ops.GetTLFHandle(ctx, nil)
	if err != nil {
		return err
	}
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	delete(fs.ops, fb)
	fav := handle.ToFavorite()
	delete(fs.opsByFav, fav)
	return nil
}

// FinishResolvingConflict implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) FinishResolvingConflict(
	ctx context.Context, fb data.FolderBranch) (err error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	fs.log.CDebugf(ctx, "FinishResolvingConflict(%v)", fb)
	defer func() {
		fs.deferLog.CDebugf(ctx, "Done: %+v", err)
	}()

	// First invalidate all its nodes and shut down the FBO.
	ops := fs.getOpsIfExists(ctx, fb)
	if ops != nil {
		err := ops.invalidateAllNodes(ctx)
		if err != nil {
			return err
		}
		err = fs.deleteOps(ctx, ops, fb)
		if err != nil {
			return err
		}
		err = ops.Shutdown(ctx)
		if err != nil {
			return err
		}
	}

	jManager, jErr := GetJournalManager(fs.config)
	if jErr == nil {
		err := jManager.FinishResolvingConflict(ctx, fb.Tlf)
		if err != nil {
			return err
		}
	}
	return nil
}

// ForceStuckConflictForTesting implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) ForceStuckConflictForTesting(
	ctx context.Context, tlfID tlf.ID) error {
	fbo := fs.getOpsNoAdd(ctx, data.FolderBranch{
		Tlf:    tlfID,
		Branch: data.MasterBranch,
	})
	return fbo.forceStuckConflictForTesting(ctx)
}

// GetSyncConfig implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) GetSyncConfig(
	ctx context.Context, tlfID tlf.ID) (keybase1.FolderSyncConfig, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx,
		data.FolderBranch{Tlf: tlfID, Branch: data.MasterBranch}, FavoritesOpNoChange)
	return ops.GetSyncConfig(ctx, tlfID)
}

// SetSyncConfig implements the KBFSOps interface for KBFSOpsStandard.
func (fs *KBFSOpsStandard) SetSyncConfig(
	ctx context.Context, tlfID tlf.ID,
	config keybase1.FolderSyncConfig) (<-chan error, error) {
	timeTrackerDone := fs.longOperationDebugDumper.Begin(ctx)
	defer timeTrackerDone()

	ops := fs.getOps(ctx,
		data.FolderBranch{Tlf: tlfID, Branch: data.MasterBranch}, FavoritesOpNoChange)
	return ops.SetSyncConfig(ctx, tlfID, config)
}

func (fs *KBFSOpsStandard) changeHandle(ctx context.Context,
	oldFav favorites.Folder, newHandle *tlfhandle.Handle) {
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	ops, ok := fs.opsByFav[oldFav]
	if !ok {
		return
	}
	newFav := newHandle.ToFavorite()
	fs.log.CDebugf(ctx, "Changing handle: %v -> %v", oldFav, newFav)
	fs.opsByFav[newFav] = ops
	delete(fs.opsByFav, oldFav)
}

// AddRootNodeWrapper implements the KBFSOps interface for
// KBFSOpsStandard.
func (fs *KBFSOpsStandard) AddRootNodeWrapper(f func(Node) Node) {
	fs.opsLock.Lock()
	defer fs.opsLock.Unlock()
	for _, op := range fs.ops {
		op.addRootNodeWrapper(f)
	}
}

// Notifier:
var _ Notifier = (*KBFSOpsStandard)(nil)

// RegisterForChanges implements the Notifer interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) RegisterForChanges(
	folderBranches []data.FolderBranch, obs Observer) error {
	for _, fb := range folderBranches {
		// TODO: add branch parameter to notifier interface
		ops := fs.getOps(context.Background(), fb, FavoritesOpNoChange)
		return ops.RegisterForChanges(obs)
	}
	return nil
}

// UnregisterFromChanges implements the Notifer interface for KBFSOpsStandard
func (fs *KBFSOpsStandard) UnregisterFromChanges(
	folderBranches []data.FolderBranch, obs Observer) error {
	for _, fb := range folderBranches {
		// TODO: add branch parameter to notifier interface
		ops := fs.getOps(context.Background(), fb, FavoritesOpNoChange)
		return ops.UnregisterFromChanges(obs)
	}
	return nil
}

func (fs *KBFSOpsStandard) onTLFBranchChange(tlfID tlf.ID, newBID kbfsmd.BranchID) {
	ops := fs.getOps(context.Background(),
		data.FolderBranch{Tlf: tlfID, Branch: data.MasterBranch}, FavoritesOpNoChange)
	ops.onTLFBranchChange(newBID) // folderBranchOps makes a goroutine
}

func (fs *KBFSOpsStandard) onMDFlush(tlfID tlf.ID, bid kbfsmd.BranchID,
	rev kbfsmd.Revision) {
	ops := fs.getOps(context.Background(),
		data.FolderBranch{Tlf: tlfID, Branch: data.MasterBranch}, FavoritesOpNoChange)
	ops.onMDFlush(bid, rev) // folderBranchOps makes a goroutine
}

func (fs *KBFSOpsStandard) initTlfsForEditHistories() {
	defer fs.editActivity.Done()
	shutdown := func() bool {
		fs.editLock.Lock()
		defer fs.editLock.Unlock()
		return fs.editShutdown
	}()
	if shutdown {
		return
	}

	if !fs.config.Mode().TLFEditHistoryEnabled() {
		return
	}

	ctx := CtxWithRandomIDReplayable(
		context.Background(), CtxFBOIDKey, CtxFBOOpID, fs.log)
	fs.log.CDebugf(ctx, "Querying the kbfs-edits inbox for new TLFs")
	handles, err := fs.config.Chat().GetGroupedInbox(
		ctx, chat1.TopicType_KBFSFILEEDIT, kbfsedits.MaxClusters)
	if err != nil {
		fs.log.CWarningf(ctx, "Can't get inbox: %+v", err)
		return
	}

	// Construct folderBranchOps instances for each TLF in the inbox
	// that doesn't have one yet.
	for _, h := range handles {
		if h.TlfID() != tlf.NullID {
			fs.log.CDebugf(ctx, "Initializing TLF %s (%s) for the edit history",
				h.GetCanonicalPath(), h.TlfID())
			// Fully initialize the TLF in order to kick off any
			// necessary prefetches.
			err := fs.initTLFWithoutIdentifyPopups(ctx, h)
			if err != nil {
				fs.log.CDebugf(ctx, "Couldn't initialize TLF: %+v", err)
				continue
			}
		} else {
			fs.log.CWarningf(ctx,
				"Handle %s for existing folder unexpectedly has no TLF ID",
				h.GetCanonicalName())
		}
	}
}

func (fs *KBFSOpsStandard) initSyncedTlfs() {
	tlfs := fs.config.GetAllSyncedTlfs()
	if len(tlfs) == 0 {
		return
	}

	ctx := CtxWithRandomIDReplayable(
		context.Background(), CtxFBOIDKey, CtxFBOOpID, fs.log)
	fs.log.CDebugf(ctx, "Initializing %d synced TLFs", len(tlfs))

	// Should we parallelize these in some limited way to speed it up
	// without overwhelming the CPU?
	for _, tlfID := range tlfs {
		fs.log.CDebugf(ctx, "Initializing synced TLF: %s", tlfID)
		md, err := fs.config.MDOps().GetForTLF(ctx, tlfID, nil)
		if err != nil {
			fs.log.CDebugf(ctx, "Couldn't initialize TLF %s: %+v", err)
			continue
		}
		if md == (ImmutableRootMetadata{}) {
			fs.log.CDebugf(ctx, "TLF %s has no revisions yet", err)
			continue
		}

		// Getting the root node populates the head of the TLF, which
		// kicks off any needed sync operations.
		err = fs.initTLFWithoutIdentifyPopups(ctx, md.GetTlfHandle())
		if err != nil {
			fs.log.CDebugf(ctx, "Couldn't initialize TLF %s: %+v", err)
			continue
		}
	}

}

// kbfsOpsFavoriteObserver deals with a handle change for a particular
// favorites.  It ignores local and batch changes.
type kbfsOpsFavoriteObserver struct {
	kbfsOps *KBFSOpsStandard

	lock    sync.Mutex
	currFav favorites.Folder
}

var _ Observer = (*kbfsOpsFavoriteObserver)(nil)

func (kofo *kbfsOpsFavoriteObserver) LocalChange(
	_ context.Context, _ Node, _ WriteRange) {
}

func (kofo *kbfsOpsFavoriteObserver) BatchChanges(
	_ context.Context, _ []NodeChange, _ []NodeID) {
}

func (kofo *kbfsOpsFavoriteObserver) TlfHandleChange(
	ctx context.Context, newHandle *tlfhandle.Handle) {
	kofo.lock.Lock()
	defer kofo.lock.Unlock()
	kofo.kbfsOps.changeHandle(ctx, kofo.currFav, newHandle)
	kofo.currFav = newHandle.ToFavorite()
}
