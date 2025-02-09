// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

//
// Code used in populating JSON objects to generating Keybase-style
// signatures.
//
package libkb

import (
	"encoding/base64"
	"errors"
	"fmt"

	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	stellar1 "github.com/keybase/client/go/protocol/stellar1"
	jsonw "github.com/keybase/go-jsonw"
)

func clientInfo(m MetaContext) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("version", jsonw.NewString(Version))
	ret.SetKey("name", jsonw.NewString(GoClientID))
	return ret
}

type KeySection struct {
	Key                  GenericKey
	EldestKID            keybase1.KID
	ParentKID            keybase1.KID
	HasRevSig            bool
	RevSig               string
	SigningUser          UserBasic
	IncludePGPHash       bool
	PerUserKeyGeneration keybase1.PerUserKeyGeneration
}

func LinkEntropy() (string, error) {
	entropyBytes, err := RandBytes(18)
	if err != nil {
		return "", fmt.Errorf("failed to generate entropy bytes: %v", err)
	}
	return base64.StdEncoding.EncodeToString(entropyBytes), nil
}

func (arg KeySection) ToJSON() (*jsonw.Wrapper, error) {
	ret := jsonw.NewDictionary()

	ret.SetKey("kid", jsonw.NewString(arg.Key.GetKID().String()))

	if arg.EldestKID != "" {
		ret.SetKey("eldest_kid", jsonw.NewString(arg.EldestKID.String()))
	}

	if arg.ParentKID != "" {
		ret.SetKey("parent_kid", jsonw.NewString(arg.ParentKID.String()))
	}

	if arg.HasRevSig {
		var revSig *jsonw.Wrapper
		if arg.RevSig != "" {
			revSig = jsonw.NewString(arg.RevSig)
		} else {
			revSig = jsonw.NewNil()
		}
		ret.SetKey("reverse_sig", revSig)
	}

	if arg.SigningUser != nil {
		ret.SetKey("host", jsonw.NewString(CanonicalHost))
		ret.SetKey("uid", UIDWrapper(arg.SigningUser.GetUID()))
		ret.SetKey("username", jsonw.NewString(arg.SigningUser.GetName()))
	}

	if arg.PerUserKeyGeneration != 0 {
		ret.SetKey("generation", jsonw.NewInt(int(arg.PerUserKeyGeneration)))
	}

	if pgp, ok := arg.Key.(*PGPKeyBundle); ok {
		fingerprint := pgp.GetFingerprint()
		ret.SetKey("fingerprint", jsonw.NewString(fingerprint.String()))
		ret.SetKey("key_id", jsonw.NewString(fingerprint.ToKeyID()))
		if arg.IncludePGPHash {
			hash, err := pgp.FullHash()
			if err != nil {
				return nil, err
			}

			ret.SetKey("full_hash", jsonw.NewString(hash))
		}
	}

	return ret, nil
}

func (u *User) ToTrackingStatementKey(errp *error) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()

	if !u.HasActiveKey() {
		*errp = fmt.Errorf("User %s doesn't have an active key", u.GetName())
	} else {
		kid := u.GetEldestKID()
		ret.SetKey("kid", jsonw.NewString(kid.String()))
		ckf := u.GetComputedKeyFamily()
		if fingerprint, exists := ckf.kf.kid2pgp[kid]; exists {
			ret.SetKey("key_fingerprint", jsonw.NewString(fingerprint.String()))
		}
	}
	return ret
}

func (u *User) ToTrackingStatementPGPKeys(errp *error) *jsonw.Wrapper {
	keys := u.GetActivePGPKeys(true)
	if len(keys) == 0 {
		return nil
	}

	ret := jsonw.NewArray(len(keys))
	for i, k := range keys {
		kd := jsonw.NewDictionary()
		kid := k.GetKID()
		fp := k.GetFingerprintP()
		kd.SetKey("kid", jsonw.NewString(kid.String()))
		if fp != nil {
			kd.SetKey("key_fingerprint", jsonw.NewString(fp.String()))
		}
		ret.SetIndex(i, kd)
	}
	return ret
}

func (u *User) ToTrackingStatementBasics(errp *error) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("username", jsonw.NewString(u.name))
	if lastIDChange, err := u.basics.AtKey("last_id_change").GetInt(); err == nil {
		ret.SetKey("last_id_change", jsonw.NewInt(lastIDChange))
	}
	if idVersion, err := u.basics.AtKey("id_version").GetInt(); err == nil {
		ret.SetKey("id_version", jsonw.NewInt(idVersion))
	}
	return ret
}

func (u *User) ToTrackingStatementSeqTail() *jsonw.Wrapper {
	mul := u.GetPublicChainTail()
	if mul == nil {
		return jsonw.NewNil()
	}
	ret := jsonw.NewDictionary()
	ret.SetKey("sig_id", jsonw.NewString(mul.SigID.ToString(true)))
	ret.SetKey("seqno", jsonw.NewInt(int(mul.Seqno)))
	ret.SetKey("payload_hash", jsonw.NewString(mul.LinkID.String()))
	return ret
}

func (u *User) ToTrackingStatement(w *jsonw.Wrapper, outcome *IdentifyOutcome) (err error) {

	track := jsonw.NewDictionary()
	if u.HasActiveKey() {
		key := u.ToTrackingStatementKey(&err)
		if key != nil {
			track.SetKey("key", key)
		}
	}
	if pgpkeys := u.ToTrackingStatementPGPKeys(&err); pgpkeys != nil {
		track.SetKey("pgp_keys", pgpkeys)
	}
	track.SetKey("seq_tail", u.ToTrackingStatementSeqTail())
	track.SetKey("basics", u.ToTrackingStatementBasics(&err))
	track.SetKey("id", UIDWrapper(u.id))
	track.SetKey("remote_proofs", outcome.TrackingStatement())

	if err != nil {
		return err
	}

	entropy, err := LinkEntropy()
	if err != nil {
		return err
	}
	track.SetKey("entropy", jsonw.NewString(entropy))

	w.SetKey("track", track)
	return err
}

func (u *User) ToUntrackingStatementBasics() *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("username", jsonw.NewString(u.name))
	return ret
}

func (u *User) ToUntrackingStatement(w *jsonw.Wrapper) (err error) {
	untrack := jsonw.NewDictionary()
	untrack.SetKey("basics", u.ToUntrackingStatementBasics())
	untrack.SetKey("id", UIDWrapper(u.GetUID()))

	entropy, err := LinkEntropy()
	if err != nil {
		return err
	}
	untrack.SetKey("entropy", jsonw.NewString(entropy))

	w.SetKey("untrack", untrack)
	return err
}

func (g *GenericChainLink) BaseToTrackingStatement(state keybase1.ProofState) *jsonw.Wrapper {
	ret := jsonw.NewDictionary()
	ret.SetKey("curr", jsonw.NewString(g.id.String()))
	ret.SetKey("sig_id", jsonw.NewString(g.GetSigID().ToString(true)))

	rkp := jsonw.NewDictionary()
	ret.SetKey("remote_key_proof", rkp)
	rkp.SetKey("state", jsonw.NewInt(int(state)))

	prev := g.GetPrev()
	var prevVal *jsonw.Wrapper
	if prev == nil {
		prevVal = jsonw.NewNil()
	} else {
		prevVal = jsonw.NewString(prev.String())
	}

	ret.SetKey("prev", prevVal)
	ret.SetKey("ctime", jsonw.NewInt64(g.unpacked.ctime))
	ret.SetKey("etime", jsonw.NewInt64(g.unpacked.etime))
	return ret
}

func remoteProofToTrackingStatement(s RemoteProofChainLink, base *jsonw.Wrapper) {
	proofType := s.GetProofType()
	base.AtKey("remote_key_proof").SetKey("proof_type", jsonw.NewInt(int(proofType)))
	base.AtKey("remote_key_proof").SetKey("check_data_json", s.CheckDataJSON())
	base.SetKey("sig_type", jsonw.NewInt(SigTypeRemoteProof))
}

type HighSkip struct {
	Seqno keybase1.Seqno
	Hash  LinkID
}

func NewHighSkip(highSkipSeqno keybase1.Seqno, highSkipHash LinkID) HighSkip {
	return HighSkip{
		Seqno: highSkipSeqno,
		Hash:  highSkipHash,
	}
}

func NewInitialHighSkip() HighSkip {
	return NewHighSkip(keybase1.Seqno(0), nil)
}

func (h HighSkip) AssertEqualsExpected(expected HighSkip) error {
	if expected.Seqno != h.Seqno {
		return fmt.Errorf("Expected highSkip.Seqno %d, got %d.", expected.Seqno, h.Seqno)
	}
	if !expected.Hash.Eq(h.Hash) {
		return fmt.Errorf("Expected highSkip.Hash %s, got %s.", expected.Hash.String(), h.Hash.String())
	}
	return nil
}

type ProofMetadata struct {
	Me                  *User
	SigningUser         UserBasic
	Seqno               keybase1.Seqno
	PrevLinkID          LinkID
	LinkType            LinkType
	SigningKey          GenericKey
	Eldest              keybase1.KID
	CreationTime        int64
	ExpireIn            int
	IncludePGPHash      bool
	SigVersion          SigVersion
	SeqType             keybase1.SeqType
	MerkleRoot          *MerkleRoot
	IgnoreIfUnsupported SigIgnoreIfUnsupported
	// HighSkipFallback is used for teams to provide for a KEX-provisisonee to
	// provide the provisioner's information as the latest high link.
	HighSkipFallback *HighSkip
}

type ProofMetadataRes struct {
	J     *jsonw.Wrapper
	Seqno keybase1.Seqno
}

func (arg ProofMetadata) merkleRootInfo(m MetaContext) (ret *jsonw.Wrapper) {
	if mr := arg.MerkleRoot; mr != nil {
		return mr.ToSigJSON()
	}
	if mc := m.G().MerkleClient; mc != nil {
		ret, _ = mc.LastRootToSigJSON(m)
	}
	return ret
}

func (arg ProofMetadata) ToJSON(m MetaContext) (*jsonw.Wrapper, error) {
	res, err := arg.ToJSON2(m)
	if err != nil {
		return nil, err
	}
	return res.J, nil
}

func (arg ProofMetadata) ToJSON2(m MetaContext) (ret *ProofMetadataRes, err error) {
	// if only Me exists, then that is the signing user too
	if arg.SigningUser == nil && arg.Me != nil {
		arg.SigningUser = arg.Me
	}

	var seqno keybase1.Seqno
	var prev *jsonw.Wrapper

	// sanity check the seqno and prev relationship
	if arg.Seqno > 1 && len(arg.PrevLinkID) == 0 {
		return nil, fmt.Errorf("can't have a seqno > 1 without a prev value")
	}

	if arg.Seqno > 0 {
		seqno = arg.Seqno
		if arg.Seqno == 1 {
			prev = jsonw.NewNil()
		} else {
			prev = jsonw.NewString(arg.PrevLinkID.String())
		}
	} else {
		if arg.Me == nil {
			return nil, fmt.Errorf("missing self user object while signing")
		}
		lastSeqno := arg.Me.sigChain().GetLastKnownSeqno()
		lastLink := arg.Me.sigChain().GetLastKnownID()
		if lastLink == nil {
			seqno = 1
			prev = jsonw.NewNil()
		} else {
			seqno = lastSeqno + 1
			prev = jsonw.NewString(lastLink.String())
		}
	}

	ctime := arg.CreationTime
	if ctime == 0 {
		ctime = m.G().Clock().Now().Unix()
	}

	ei := arg.ExpireIn
	if ei == 0 {
		ei = SigExpireIn
	}

	j := jsonw.NewDictionary()
	j.SetKey("tag", jsonw.NewString("signature"))
	j.SetKey("ctime", jsonw.NewInt64(ctime))
	j.SetKey("expire_in", jsonw.NewInt(ei))
	j.SetKey("seqno", jsonw.NewInt64(int64(seqno)))
	j.SetKey("prev", prev)

	var highSkip *HighSkip
	allowHighSkips := m.G().Env.GetFeatureFlags().HasFeature(EnvironmentFeatureAllowHighSkips)
	if allowHighSkips {
		if (arg.Me != nil) && (arg.HighSkipFallback != nil) {
			return nil, fmt.Errorf("arg.Me and arg.HighSkipFallback can't both be non-nil.")
		} else if arg.Me != nil {
			highSkipPre, err := arg.Me.GetExpectedNextHighSkip(m)
			if err != nil {
				return nil, err
			}
			highSkip = &highSkipPre
		} else if arg.HighSkipFallback != nil {
			highSkip = arg.HighSkipFallback
		}

		if highSkip != nil {
			highSkipObj := jsonw.NewDictionary()
			highSkipObj.SetKey("seqno", jsonw.NewInt64(int64(highSkip.Seqno)))
			if hash := highSkip.Hash; hash != nil {
				highSkipObj.SetKey("hash", jsonw.NewString(hash.String()))
			} else {
				highSkipObj.SetKey("hash", jsonw.NewNil())
			}
			j.SetKey("high_skip", highSkipObj)
		}
	}

	if arg.IgnoreIfUnsupported {
		j.SetKey("ignore_if_unsupported", jsonw.NewBool(true))
	}
	eldest := arg.Eldest
	if eldest == "" {
		if arg.Me == nil {
			return nil, fmt.Errorf("missing self user object while signing")
		}
		eldest = arg.Me.GetEldestKID()
	}

	body := jsonw.NewDictionary()

	if arg.SigVersion != 0 {
		body.SetKey("version", jsonw.NewInt(int(arg.SigVersion)))
	} else {
		body.SetKey("version", jsonw.NewInt(int(KeybaseSignatureV1)))
	}

	body.SetKey("type", jsonw.NewString(string(arg.LinkType)))

	key, err := KeySection{
		Key:            arg.SigningKey,
		EldestKID:      eldest,
		SigningUser:    arg.SigningUser,
		IncludePGPHash: arg.IncludePGPHash,
	}.ToJSON()
	if err != nil {
		return nil, err
	}
	body.SetKey("key", key)
	// Capture the most recent Merkle Root, inside of "body"
	// field.
	if mr := arg.merkleRootInfo(m); mr != nil {
		body.SetKey("merkle_root", mr)
	}

	j.SetKey("body", body)

	// Save what kind of client we're running.
	j.SetKey("client", clientInfo(m))

	if arg.SeqType != 0 {
		j.SetKey("seq_type", jsonw.NewInt(int(arg.SeqType)))
	}

	return &ProofMetadataRes{
		J:     j,
		Seqno: seqno,
	}, err
}

func (u *User) TrackingProofFor(m MetaContext, signingKey GenericKey, sigVersion SigVersion, u2 *User, outcome *IdentifyOutcome) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeTrack,
		SigningKey: signingKey,
		SigVersion: sigVersion,
	}.ToJSON2(m)
	if err == nil {
		err = u2.ToTrackingStatement(ret.J.AtKey("body"), outcome)
	}
	return ret, err
}

func (u *User) UntrackingProofFor(m MetaContext, signingKey GenericKey, sigVersion SigVersion, u2 *User) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeUntrack,
		SigningKey: signingKey,
		SigVersion: sigVersion,
	}.ToJSON2(m)
	if err == nil {
		err = u2.ToUntrackingStatement(ret.J.AtKey("body"))
	}
	return ret, err
}

// arg.Me user is used to get the last known seqno in ProofMetadata.
// If arg.Me == nil, set arg.Seqno.
func KeyProof(m MetaContext, arg Delegator) (*jsonw.Wrapper, error) {
	res, err := KeyProof2(m, arg)
	if err != nil {
		return nil, err
	}
	return res.J, nil
}

// arg.Me user is used to get the last known seqno in ProofMetadata.
// If arg.Me == nil, set arg.Seqno.
func KeyProof2(m MetaContext, arg Delegator) (ret *ProofMetadataRes, err error) {
	var kp *jsonw.Wrapper
	includePGPHash := false

	if arg.DelegationType == DelegationTypeEldest {
		includePGPHash = true
	} else if arg.NewKey != nil {
		keySection := KeySection{
			Key: arg.NewKey,
		}
		switch arg.DelegationType {
		case DelegationTypePGPUpdate:
			keySection.IncludePGPHash = true
		case DelegationTypeSibkey:
			keySection.HasRevSig = true
			keySection.RevSig = arg.RevSig
			keySection.IncludePGPHash = true
		default:
			keySection.ParentKID = arg.ExistingKey.GetKID()
		}

		if kp, err = keySection.ToJSON(); err != nil {
			return nil, err
		}
	}

	// Only set the fallback for subkeys during KEX where arg.Me == nil; it is
	// otherwise updated using me.SigChainBump().
	var highSkipFallback *HighSkip
	if arg.Me == nil && arg.DelegationType == DelegationTypeSubkey {
		highSkip := NewHighSkip(arg.Seqno-1, arg.PrevLinkID)
		highSkipFallback = &highSkip
	}

	ret, err = ProofMetadata{
		Me:               arg.Me,
		SigningUser:      arg.SigningUser,
		LinkType:         LinkType(arg.DelegationType),
		ExpireIn:         arg.Expire,
		SigningKey:       arg.GetSigningKey(),
		Eldest:           arg.EldestKID,
		CreationTime:     arg.Ctime,
		IncludePGPHash:   includePGPHash,
		Seqno:            arg.Seqno,
		HighSkipFallback: highSkipFallback,
		PrevLinkID:       arg.PrevLinkID,
		MerkleRoot:       arg.MerkleRoot,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}

	body := ret.J.AtKey("body")

	if arg.Device != nil {
		device := *arg.Device
		device.Kid = arg.NewKey.GetKID()
		var dw *jsonw.Wrapper
		dw, err = device.Export(LinkType(arg.DelegationType))
		if err != nil {
			return nil, err
		}
		body.SetKey("device", dw)
	}
	if kp != nil {
		body.SetKey(string(arg.DelegationType), kp)
	}
	return ret, nil
}

func (u *User) ServiceProof(m MetaContext, signingKey GenericKey, typ ServiceType, remotename string, sigVersion SigVersion) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeWebServiceBinding,
		SigningKey: signingKey,
		SigVersion: sigVersion,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}
	service := typ.ToServiceJSON(remotename)
	entropy, err := LinkEntropy()
	if err != nil {
		return nil, err
	}
	service.SetKey("entropy", jsonw.NewString(entropy))
	ret.J.AtKey("body").SetKey("service", service)
	return ret, err
}

// SimpleSignJson marshals the given Json structure and then signs it.
func SignJSON(jw *jsonw.Wrapper, key GenericKey) (out string, id keybase1.SigID, lid LinkID, err error) {
	var tmp []byte
	if tmp, err = jw.Marshal(); err != nil {
		return
	}
	out, id, err = key.SignToString(tmp)
	lid = ComputeLinkID(tmp)
	return
}

func GetDefaultSigVersion(g *GlobalContext) SigVersion {
	return KeybaseSignatureV2
}

func MakeSig(
	m MetaContext,
	signingKey GenericKey,
	v1LinkType LinkType,
	innerLinkJSON []byte,
	hasRevokes SigHasRevokes,
	seqType keybase1.SeqType,
	ignoreIfUnsupported SigIgnoreIfUnsupported,
	me *User,
	sigVersion SigVersion) (sig string, sigID keybase1.SigID, linkID LinkID, err error) {
	switch sigVersion {
	case KeybaseSignatureV1:
		sig, sigID, err = signingKey.SignToString(innerLinkJSON)
		linkID = ComputeLinkID(innerLinkJSON)
	case KeybaseSignatureV2:
		prevSeqno := me.GetSigChainLastKnownSeqno()
		prevLinkID := me.GetSigChainLastKnownID()
		highSkip, highSkipErr := me.GetExpectedNextHighSkip(m)
		if highSkipErr != nil {
			return sig, sigID, linkID, highSkipErr
		}
		sig, sigID, linkID, err = MakeSigchainV2OuterSig(
			m,
			signingKey,
			v1LinkType,
			prevSeqno+1,
			innerLinkJSON,
			prevLinkID,
			hasRevokes,
			seqType,
			ignoreIfUnsupported,
			&highSkip,
		)
	default:
		err = errors.New("Invalid Signature Version")
	}
	return sig, sigID, linkID, err
}

func (u *User) RevokeKeysProof(m MetaContext, key GenericKey, kidsToRevoke []keybase1.KID,
	deviceToDisable keybase1.DeviceID, merkleRoot *MerkleRoot) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeRevoke,
		SigningKey: key,
		MerkleRoot: merkleRoot,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}
	body := ret.J.AtKey("body")
	revokeSection := jsonw.NewDictionary()
	revokeSection.SetKey("kids", jsonw.NewWrapper(kidsToRevoke))
	body.SetKey("revoke", revokeSection)
	if deviceToDisable.Exists() {
		device, err := u.GetDevice(deviceToDisable)
		if err != nil {
			return nil, err
		}
		deviceSection := jsonw.NewDictionary()
		deviceSection.SetKey("id", jsonw.NewString(deviceToDisable.String()))
		deviceSection.SetKey("type", jsonw.NewString(device.Type))
		deviceSection.SetKey("status", jsonw.NewInt(DeviceStatusDefunct))
		body.SetKey("device", deviceSection)
	}
	return ret, nil
}

func (u *User) RevokeSigsProof(m MetaContext, key GenericKey, sigIDsToRevoke []keybase1.SigID, merkleRoot *MerkleRoot) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeRevoke,
		SigningKey: key,
		MerkleRoot: merkleRoot,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}
	body := ret.J.AtKey("body")
	revokeSection := jsonw.NewDictionary()
	idsArray := jsonw.NewArray(len(sigIDsToRevoke))
	for i, id := range sigIDsToRevoke {
		idsArray.SetIndex(i, jsonw.NewString(id.ToString(true)))
	}
	revokeSection.SetKey("sig_ids", idsArray)
	body.SetKey("revoke", revokeSection)
	return ret, nil
}

func (u *User) CryptocurrencySig(m MetaContext, key GenericKey, address string, typ CryptocurrencyType, sigToRevoke keybase1.SigID, merkleRoot *MerkleRoot, sigVersion SigVersion) (*ProofMetadataRes, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeCryptocurrency,
		SigningKey: key,
		MerkleRoot: merkleRoot,
		SigVersion: sigVersion,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}
	body := ret.J.AtKey("body")
	currencySection := jsonw.NewDictionary()
	currencySection.SetKey("address", jsonw.NewString(address))
	currencySection.SetKey("type", jsonw.NewString(typ.String()))
	entropy, err := LinkEntropy()
	if err != nil {
		return nil, err
	}
	currencySection.SetKey("entropy", jsonw.NewString(entropy))
	body.SetKey("cryptocurrency", currencySection)
	if len(sigToRevoke) > 0 {
		revokeSection := jsonw.NewDictionary()
		revokeSection.SetKey("sig_id", jsonw.NewString(sigToRevoke.ToString(true /* suffix */)))
		body.SetKey("revoke", revokeSection)
	}
	return ret, nil
}

func (u *User) UpdatePassphraseProof(m MetaContext, key GenericKey, pwh string, ppGen PassphraseGeneration, pdpka5kid string) (*jsonw.Wrapper, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeUpdatePassphrase,
		SigningKey: key,
	}.ToJSON(m)
	if err != nil {
		return nil, err
	}
	body := ret.AtKey("body")
	pp := jsonw.NewDictionary()
	pp.SetKey("hash", jsonw.NewString(pwh))
	pp.SetKey("pdpka5_kid", jsonw.NewString(pdpka5kid))
	pp.SetKey("version", jsonw.NewInt(int(ClientTriplesecVersion)))
	pp.SetKey("passphrase_generation", jsonw.NewInt(int(ppGen)))
	body.SetKey("update_passphrase_hash", pp)
	return ret, nil
}

func (u *User) UpdateEmailProof(m MetaContext, key GenericKey, newEmail string) (*jsonw.Wrapper, error) {
	ret, err := ProofMetadata{
		Me:         u,
		LinkType:   LinkTypeUpdateSettings,
		SigningKey: key,
	}.ToJSON(m)
	if err != nil {
		return nil, err
	}
	body := ret.AtKey("body")
	settings := jsonw.NewDictionary()
	settings.SetKey("email", jsonw.NewString(newEmail))
	body.SetKey("update_settings", settings)
	return ret, nil
}

type SigMultiItem struct {
	Sig3       string                  `json:"sig3,omitempty"`
	Sig        string                  `json:"sig,omitempty"`
	SigningKID keybase1.KID            `json:"signing_kid"`
	Type       string                  `json:"type"`
	SeqType    keybase1.SeqType        `json:"seq_type"`
	SigInner   string                  `json:"sig_inner"`
	TeamID     keybase1.TeamID         `json:"team_id"`
	PublicKeys *SigMultiItemPublicKeys `json:"public_keys,omitempty"`
	Version    SigVersion              `json:"version"`
}

type SigMultiItemPublicKeys struct {
	Encryption keybase1.KID `json:"encryption"`
	Signing    keybase1.KID `json:"signing"`
}

// PerUserKeyProof creates a proof introducing a new per-user-key generation.
// `signingKey` is the key signing in this new key. Not to be confused with the derived per-user-key signing key.
func PerUserKeyProof(m MetaContext,
	me *User,
	pukSigKID keybase1.KID,
	pukEncKID keybase1.KID,
	generation keybase1.PerUserKeyGeneration,
	signingKey GenericKey) (*ProofMetadataRes, error) {

	if me == nil {
		return nil, fmt.Errorf("missing user object for proof")
	}

	ret, err := ProofMetadata{
		Me:         me,
		LinkType:   LinkTypePerUserKey,
		SigningKey: signingKey,
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}

	pukSection := jsonw.NewDictionary()
	pukSection.SetKey("signing_kid", jsonw.NewString(pukSigKID.String()))
	pukSection.SetKey("encryption_kid", jsonw.NewString(pukEncKID.String()))
	pukSection.SetKey("generation", jsonw.NewInt(int(generation)))
	// The caller is responsible for overwriting reverse_sig after signing.
	pukSection.SetKey("reverse_sig", jsonw.NewNil())

	body := ret.J.AtKey("body")
	body.SetKey("per_user_key", pukSection)

	return ret, nil
}

type UserLinkSignature struct {
	Payload JSONPayload
	Seqno   keybase1.Seqno
	LinkID  LinkID
}

// Make a per-user key proof with a reverse sig.
// Modifies the User `me` with a sigchain bump and key delegation.
// Returns a JSONPayload ready for use in "sigs" in sig/multi.
func PerUserKeyProofReverseSigned(m MetaContext, me *User, perUserKeySeed PerUserKeySeed, generation keybase1.PerUserKeyGeneration,
	signer GenericKey) (*UserLinkSignature, error) {

	pukSigKey, err := perUserKeySeed.DeriveSigningKey()
	if err != nil {
		return nil, err
	}

	pukEncKey, err := perUserKeySeed.DeriveDHKey()
	if err != nil {
		return nil, err
	}

	// Make reverse sig
	forward, err := PerUserKeyProof(m, me, pukSigKey.GetKID(), pukEncKey.GetKID(), generation, signer)
	if err != nil {
		return nil, err
	}
	reverseSig, _, _, err := SignJSON(forward.J, pukSigKey)
	if err != nil {
		return nil, err
	}

	// Make sig
	jw := forward.J
	jw.SetValueAtPath("body.per_user_key.reverse_sig", jsonw.NewString(reverseSig))
	sig, sigID, linkID, err := SignJSON(jw, signer)
	if err != nil {
		return nil, err
	}

	// Update the user locally
	me.SigChainBump(linkID, sigID, false)
	me.localDelegatePerUserKey(keybase1.PerUserKey{
		Gen:         int(generation),
		Seqno:       me.GetSigChainLastKnownSeqno(),
		SigKID:      pukSigKey.GetKID(),
		EncKID:      pukEncKey.GetKID(),
		SignedByKID: signer.GetKID(),
	})

	publicKeysEntry := make(JSONPayload)
	publicKeysEntry["signing"] = pukSigKey.GetKID().String()
	publicKeysEntry["encryption"] = pukEncKey.GetKID().String()

	payload := make(JSONPayload)
	payload["sig"] = sig
	payload["signing_kid"] = signer.GetKID().String()
	payload["type"] = LinkTypePerUserKey
	payload["public_keys"] = publicKeysEntry
	return &UserLinkSignature{
		Payload: payload,
		Seqno:   forward.Seqno,
		LinkID:  linkID,
	}, nil
}

// StellarProof creates a proof of a stellar wallet.
func StellarProof(m MetaContext, me *User, walletAddress stellar1.AccountID,
	signingKey GenericKey) (*ProofMetadataRes, error) {
	if me == nil {
		return nil, fmt.Errorf("missing user object for proof")
	}
	walletPubKey, err := MakeNaclSigningKeyPairFromStellarAccountID(walletAddress)
	if err != nil {
		return nil, err
	}
	walletKID := walletPubKey.GetKID()

	ret, err := ProofMetadata{
		Me:                  me,
		LinkType:            LinkTypeWalletStellar,
		SigningKey:          signingKey,
		SigVersion:          KeybaseSignatureV2,
		IgnoreIfUnsupported: SigIgnoreIfUnsupported(true),
	}.ToJSON2(m)
	if err != nil {
		return nil, err
	}

	walletSection := jsonw.NewDictionary()
	walletSection.SetKey("address", jsonw.NewString(walletAddress.String()))
	walletSection.SetKey("network", jsonw.NewString(string(WalletNetworkStellar)))

	// Inner links can be hidden. To prevent an attacker from figuring out the
	// contents from the hash of the inner link, add 18 random bytes.
	entropy, err := LinkEntropy()
	if err != nil {
		return nil, err
	}
	walletSection.SetKey("entropy", jsonw.NewString(entropy))

	walletKeySection := jsonw.NewDictionary()
	walletKeySection.SetKey("kid", jsonw.NewString(walletKID.String()))
	// The caller is responsible for overwriting reverse_sig after signing.
	walletKeySection.SetKey("reverse_sig", jsonw.NewNil())

	body := ret.J.AtKey("body")
	body.SetKey("wallet", walletSection)
	body.SetKey("wallet_key", walletKeySection)

	return ret, nil
}

// Make a stellar proof with a reverse sig.
// Modifies the User `me` with a sigchain bump and key delegation.
// Returns a JSONPayload ready for use in "sigs" in sig/multi.
func StellarProofReverseSigned(m MetaContext, me *User, walletAddress stellar1.AccountID,
	stellarSigner stellar1.SecretKey, deviceSigner GenericKey) (*UserLinkSignature, error) {
	// Make reverse sig
	forward, err := StellarProof(m, me, walletAddress, deviceSigner)
	if err != nil {
		return nil, err
	}
	stellarSignerKey, err := MakeNaclSigningKeyPairFromStellarSecretKey(stellarSigner)
	if err != nil {
		return nil, err
	}
	reverseSig, _, linkID, err := SignJSON(forward.J, stellarSignerKey)
	if err != nil {
		return nil, err
	}

	// Make sig
	jw := forward.J
	jw.SetValueAtPath("body.wallet_key.reverse_sig", jsonw.NewString(reverseSig))
	innerJSON, err := jw.Marshal()
	if err != nil {
		return nil, err
	}
	sig, sigID, linkID, err := MakeSig(
		m,
		deviceSigner,
		LinkTypeWalletStellar,
		innerJSON,
		SigHasRevokes(false),
		keybase1.SeqType_PUBLIC,
		SigIgnoreIfUnsupported(true),
		me,
		KeybaseSignatureV2,
	)
	if err != nil {
		return nil, err
	}

	// Update the user locally
	me.SigChainBump(linkID, sigID, false)
	// TODO: do we need to locally do something like me.localDelegatePerUserKey?

	payload := make(JSONPayload)
	payload["sig"] = sig
	payload["sig_inner"] = string(innerJSON)
	payload["signing_kid"] = deviceSigner.GetKID().String()
	payload["public_key"] = stellarSignerKey.GetKID().String()
	payload["type"] = LinkTypeWalletStellar
	return &UserLinkSignature{
		Payload: payload,
		Seqno:   forward.Seqno,
		LinkID:  linkID,
	}, nil
}
