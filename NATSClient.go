package natsclient

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/awgh/bencrypt/bc"
	"github.com/awgh/bencrypt/ecc"
	"github.com/nats-io/nats.go"
	"github.com/patrickmn/go-cache"
	_ "golang.org/x/crypto/openpgp"
)

type TokenKeyCache struct {
	Token   string
	SessKey *ecc.KeyPair
}

var (
	libnc         *nats.Conn
	SessionKey    *ecc.KeyPair
	SessionPubKey string
	ServerKey     *ecc.KeyPair
	ServerPubKey  string // sent to server calls for encryption of result message
	ServerToken   APIToken
	// set in APILogin call
	DPSessKeyCache *cache.Cache
)

func init() {

	DPSessKeyCache = cache.New(8*time.Hour, 8*time.Hour) // Session Key cache expires with JWT
}

func genKey() *ecc.KeyPair {

	SessionKey = new(ecc.KeyPair)
	SessionKey.GenerateKey()
	return SessionKey

}

func GenKey() *ecc.KeyPair {

	SessionKey = new(ecc.KeyPair)
	SessionKey.GenerateKey()
	return SessionKey

}

func GetSessionKey(token string) *ecc.KeyPair {

	//fmt.Printf("sess token %v\n", req.Header.Authorization)
	sKey, found := DPSessKeyCache.Get(token)
	if !found {
		fmt.Printf("GetSessionKey: no session key\n")
		return nil
	} else {
		//sessKey = sKey.(*ecc.KeyPair)
		return sKey.(*ecc.KeyPair)
	}
	//fmt.Printf("sess key %v pubkey %v\n", sessKey, sessKey.GetPubKey())
}

func SessionKeyNilError() *NATSResponse {
	response := &NATSResponse{}
	response.Header.Status = http.StatusRequestTimeout
	response.Header.ErrorStr = "session key timeout"
	return response
}

type APIToken struct {
	Token   string `json:"token"`
	SPubKey string `json:"pubKey"`
}

func _Encrypt(data []byte, key *ecc.KeyPair) []byte {
	//encrypted := data
	// catch panic from encryption invalid key
	defer func() {
		if err := recover(); err != nil {
			log.Println("_encrypt panic occurred:", err)
		}
	}()
	encrypted, err := key.EncryptMessage(data, key.GetPubKey())
	if err != nil {
		fmt.Printf("encrypt err: %v\n", err)
		return []byte("")
	}
	return encrypted
}

func _Decrypt(encrypted []byte, key *ecc.KeyPair) []byte {

	//decrypted := encrypted
	// catch panic from decrypt invalid key
	defer func() {
		if err := recover(); err != nil {
			log.Println("_decrypt panic occurred:", err)
		}
	}()
	_, decrypted, err := key.DecryptMessage(encrypted)
	if err != nil {
		fmt.Printf("decrypt err: %v\n", err)
		return []byte("")
	}

	return decrypted
}

func dpEncrypt(data []byte) []byte {
	encrypted, err := ServerKey.EncryptMessage(data, ServerKey.GetPubKey())
	if err != nil {
		fmt.Printf("encrypt err: %v\n", err)
		return []byte("")
	}
	return encrypted
}

func dpDecrypt(data []byte) ([]byte, error) {
	_, decrypted, err := ServerKey.DecryptMessage(data)
	return decrypted, err
}

func getServerPubKey(server string) APIToken {

	// generate unique key pair for encrypt/decrypt
	SessionKey = genKey()

	thdr := NATSReqHeader{
		Mode:       "POST",
		Path:       "/api/serverkey",
		SessPubkey: SessionKey.GetPubKey().ToB64(), // set public key to encrypt further server requests
	}

	trec := &NATSRequest{
		Header: thdr,
		Body:   nil,
	}
	payload, err := json.Marshal(trec)
	if err != nil {
		fmt.Printf("trec err %v\n", err)
	}

	msg, err := libnc.Request(server, payload, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		dmsg := _Decrypt(msg.Data, SessionKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != http.StatusOK {
			return APIToken{}
		}
		rsp := APIToken{}
		err = json.Unmarshal([]byte(response.Response), rsp)
		ServerKey = genKey()
		ServerKey.GetPubKey().FromB64(rsp.SPubKey)
		ServerToken = APIToken{
			Token:   "server",
			SPubKey: ServerKey.GetPubKey().ToB64(),
		}
		ServerPubKey = string(ServerKey.GetPubKey().ToB64())
		err = DPSessKeyCache.Replace(ServerToken.Token, ServerKey, cache.DefaultExpiration) // any previous entry
		if err != nil {                                                                     // add new entry
			DPSessKeyCache.Set(ServerToken.Token, ServerKey, cache.DefaultExpiration)
		}
		fmt.Printf("server token %v %v\n", ServerToken.Token, ServerToken.SPubKey)
		return ServerToken
	}
	return APIToken{}
}

func LoginAPI(server, user, passCode string) APIToken {

	type User struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Expires  uint64 `json:"expires"`
	}

	token := APIToken{}

	tbodyS := User{
		Username: user,
		Password: passCode,
		Expires:  999999999999,
	}
	tbody, err := json.Marshal(tbodyS)
	if err != nil {
		fmt.Printf("tbody err %v\n", err)
	}

	// generate unique key pair for encrypt/decrypt this login session
	sessKey := genKey()

	thdr := NATSReqHeader{
		Mode:       "POST",
		Path:       "/api/login",
		SessPubkey: sessKey.GetPubKey().ToB64(), // set public key to decrypt further server responses
	}

	trec := &NATSRequest{
		Header: thdr,
		Body:   tbody,
	}
	payload, err := json.Marshal(trec)
	if err != nil {
		fmt.Printf("trec err %v\n", err)
	}

	msg, err := libnc.Request(server, payload, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != http.StatusOK {
			return APIToken{}
		}
		err = json.Unmarshal([]byte(response.Response), &token)
		err = DPSessKeyCache.Replace(token.Token, sessKey, cache.DefaultExpiration) // any previous entry
		if err != nil {                                                             // add new entry
			DPSessKeyCache.Set(token.Token, sessKey, cache.DefaultExpiration)
		}

		if ServerKey == nil {
			ServerKey = genKey()
			ServerKey.GetPubKey().FromB64(token.SPubKey)
			ServerPubKey = token.SPubKey
		}
		return APIToken{
			Token:   token.Token,
			SPubKey: token.SPubKey,
		}
	} else {
		return APIToken{}
	}
}

type CFSLConfig struct {
	User string `json:"user"`
	//Token        APIToken `json:"token"`
	Company      string `json:"company"`
	Email        string `json:"email"`
	Os           string `json:"os"`
	Expiration   uint64 `json:"expiration"`
	License      string `json:"license"`
	ServerType   string `json:"serverType"`
	MaxInstances int    `json:"maxinstances"`
	MaxFSMemory  int    `json:"maxfsmemory"`
	MaxNumFS     int    `json:"maxnumFS"`
}

func CFSInit(server string, body []byte) *CFSLConfig {
	var cfslconfig = CFSLConfig{}
	err := json.Unmarshal(body, &cfslconfig)
	if err != nil {
		return nil
	}
	return &cfslconfig

}

func GetCFSLicense(server string, token APIToken, body []byte) *CFSLConfig {
	eflags := make(map[string]interface{})
	eflags["type"] = "cfs"
	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		fmt.Printf("no session key\n")
		return nil
	}

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/api/loadlicense",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	erec := &NATSRequest{
		Header: ehdr,
		Body:   body,
	}

	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		//sessKey := GetSessionKey(token.Token)
		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			return nil
		} else {
			return CFSInit(server, response.Response)
		}
	}
	return nil
}

func SysAdminRegister(server, identity, passCode string, token APIToken, roles, groups string) (passCd string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity
	eflags["passCode"] = passCode
	eflags["roles"] = roles
	eflags["groups"] = groups

	var tempSessionKey *ecc.KeyPair

	//SessionKey = GetSessionKey(token.Token)
	if token.Token == "server" {
		// create temp sessKey for this if not logged in
		tempSessionKey = genKey()
	} else {
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusUnprocessableEntity
		}
	}

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/sysadm/register",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    tempSessionKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	fmt.Printf("Server Key %v\n", ServerKey)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		//sessKey := GetSessionKey(token.Token)
		dmsg := _Decrypt(msg.Data, tempSessionKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			passCd = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			passCd = string(response.Response)
			status = response.Header.Status
		}
	}
	return passCd, status
}

func EntityRegister(server, identity string, token APIToken,
	roles, groups, queue string, genesis, body []byte) (passCd string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity
	eflags["roles"] = roles
	eflags["groups"] = groups
	eflags["queueID"] = queue
	eflags["genesis"] = genesis

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/entity/register",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    SessionKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	erec := &NATSRequest{
		Header: ehdr,
		Body:   body,
	}

	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusNetworkAuthenticationRequired
		}
		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			passCd = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			passCd = string(response.Response)
			status = response.Header.Status
		}
	}
	return passCd, status
}

func RelationRetrieve(server, identity string, token APIToken) (resp string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}

	ehdr := NATSReqHeader{
		Mode:          "GET",
		Path:          "/relation/retrieve",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusNetworkAuthenticationRequired
		}

		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status

}

func RelationRemove(server, identity string, token APIToken) (resp string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/relation/remove",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusNetworkAuthenticationRequired
		}

		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status

}

func RelationRegister(server, identity string, token APIToken, mode string) (resp string, status int) {

	eflags := make(map[string]interface{})
	eflags["identity"] = identity
	eflags["mode"] = mode

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}

	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/relation/register",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusNetworkAuthenticationRequired
		}
		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status
}

func EntityRetrieve(server, identity string, token APIToken) (resp string, status int) {
	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	sessKey := GetSessionKey(token.Token) // get session key matching this login token
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}
	ehdr := NATSReqHeader{
		Mode:          "GET",
		Path:          "/entity/retrieve",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	status = http.StatusNotAcceptable
	resp = ""
	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusUnprocessableEntity
		}

		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status
}

func EntityUpdate(server, identity string, token APIToken, body []byte) (resp string, status int) {
	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	sessKey := GetSessionKey(token.Token) // get session key matching this login token
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}
	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/entity/update",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   body,
	}

	status = http.StatusNotAcceptable
	resp = ""
	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusUnprocessableEntity
		}

		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status
}

func EntityRemove(server, identity string, token APIToken) (resp string, status int) {
	eflags := make(map[string]interface{})
	eflags["identity"] = identity

	sessKey := GetSessionKey(token.Token) // get session key matching this login token
	if sessKey == nil {
		return "", http.StatusRequestTimeout
	}
	ehdr := NATSReqHeader{
		Mode:          "POST",
		Path:          "/entity/remove",
		Flags:         eflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}
	erec := &NATSRequest{
		Header: ehdr,
		Body:   nil,
	}

	status = http.StatusNotAcceptable
	resp = ""
	payload, err := json.Marshal(erec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if err == nil {
		var response = &NATSResponse{}
		sessKey := GetSessionKey(token.Token)
		if sessKey == nil {
			return "", http.StatusUnprocessableEntity
		}

		dmsg := _Decrypt(msg.Data, sessKey)
		err = json.Unmarshal(dmsg, response)
		if response.Header.Status != 200 {
			resp = response.Header.ErrorStr
			status = response.Header.Status
		} else {
			resp = string(response.Response)
			status = response.Header.Status
		}
	}
	return resp, status
}

func SetTag(dopts Dopts, val string) {
	dopts["k"] = val
}

func SetVal(dopts Dopts, val string) {
	dopts["v"] = val
}

func SetMatch(dopts Dopts, val string) {
	dopts["q"] = val
}

func SetWithHeaders(dopts Dopts, val string) {
	dopts["withHeaders"] = val
}

func SetSecureHeader(dopts Dopts, val string) {
	dopts["secureHeader"] = val
}

func SetEntityAccess(dopts Dopts, val string) {
	dopts["entityAccess"] = val
}

func SetExpiry(dopts Dopts, val string) {
	dopts["expiry"] = val
}

func SetNoHeaders(dopts Dopts, val string) {
	dopts["noHeaders"] = val
}

func SetTimestamp(dopts Dopts, val string) {
	dopts["timestamp"] = val
}

func SetEncryptDataPKey(dopts Dopts, val string) {
	dopts["encryptDataPKey"] = val
}

func SetDomain(dopts Dopts, val string) {
	dopts["domain"] = val
}

func SetEntity(dopts Dopts, val string) {
	dopts["entity"] = val
}

func SetRDID(dopts Dopts, val string) {
	dopts["rdid"] = val
}

func SetAspect(dopts Dopts, val string) {
	dopts["aspect"] = val
}

func SetDocId(dopts Dopts, val string) {
	dopts["id"] = val
}

func SetCount(dopts Dopts, val string) {
	dopts["count"] = val
}

func SetRoles(dopts Dopts, val string) {
	dopts["roles"] = val
}

func SetGroups(dopts Dopts, val string) {
	dopts["groups"] = val
}

func SetContentType(dopts Dopts, val string) {
	dopts["Content-Type"] = val
}

func Get(server string, dopts Dopts, token APIToken) *NATSResponse {
	dflags := make(map[string]interface{})
	if dopts["withHeaders"] != nil {
		dflags["withHeaders"] = dopts["withHeaders"].(string)
	}
	if dopts["noHeaders"] != nil {
		dflags["noHeaders"] = dopts["noHeaders"].(string)
	}
	if dopts["timestamp"] != nil {
		dflags["timestamp"] = dopts["timestamp"].(string)
	}
	if dopts["encryptDataPKey"] != nil {
		dflags["encryptDataPKey"] = dopts["encryptDataPKey"].(string)
	}
	if dopts["domain"] != nil {
		dflags["domain"] = dopts["domain"].(string)
	}
	if dopts["entity"] != nil {
		dflags["entity"] = dopts["entity"].(string)
	}
	if dopts["rdid"] != nil {
		dflags["rdid"] = dopts["rdid"].(string)
	}
	if dopts["aspect"] != nil {
		dflags["aspect"] = dopts["aspect"].(string)
	}
	if dopts["id"] != nil {
		dflags["id"] = dopts["id"].(string)
	}
	if dopts["k"] != nil {
		dflags["k"] = dopts["k"].(string)
	}
	if dopts["v"] != nil {
		dflags["v"] = dopts["v"].(string)
	}
	if dopts["q"] != nil {
		dflags["q"] = dopts["q"].(string)
	}
	if dopts["count"] != nil {
		dflags["count"] = dopts["count"].(bool)
	}

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return SessionKeyNilError()
	}

	mode := "GET"
	dhdr := NATSReqHeader{
		Mode:          mode,
		Flags:         dflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	if dflags["rdid"] == nil {
		dhdr.Path = fmt.Sprintf("/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["aspect"])

	} else if dflags["id"] != nil {
		dhdr.Path = fmt.Sprintf("/%v/%v/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["rdid"], dflags["aspect"], dflags["id"])
	} else {
		dhdr.Path = fmt.Sprintf("/%v/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["rdid"], dflags["aspect"])
	}

	replyTo := libnc.NewRespInbox()
	dhdr.ReplyTo = replyTo

	drec := &NATSRequest{
		Header: dhdr,
		Body:   nil,
	}

	response := &NATSResponse{}
	payload, err := json.Marshal(drec)
	encrypted := dpEncrypt(payload)

	msg, err := libnc.Request(server, encrypted, 50*time.Second)
	if msg.Reply != "OK" {

	}

	s, err := libnc.SubscribeSync(replyTo)
	if err != nil {
		fmt.Printf("subscribe err %v\n", err)
	}
	libnc.Flush()

	_, err = libnc.Request(server, encrypted, 60*time.Second)

	if err != nil {
		response.Header.Status = http.StatusBadGateway
		if libnc.LastError() != nil {
			log.Printf("%v for request", libnc.LastError())
			response.Header.ErrorStr = fmt.Sprintf("%v for request", libnc.LastError())
		}
		log.Printf("%v for request", err)
		response.Header.ErrorStr = fmt.Sprintf("%v for request", err)
	}

	retries := 25
	for { // try for 1000 miliseconds at a time, one sec up to 25 secs
		msg, err := s.NextMsg(1000 * time.Millisecond)
		if err != nil {
			if err.Error() != "nats: timeout" {
				fmt.Printf("msg err %v \n", err)
			}
		}

		if err == nil && msg != nil {
			sessKey := GetSessionKey(token.Token)
			if sessKey == nil {
				response.Header.Status = http.StatusNetworkAuthenticationRequired
				response.Header.ErrorStr = "session key expired"
				return response
			}

			rmsg := _Decrypt(msg.Data, sessKey)
			err = json.Unmarshal(rmsg, response)
			if err != nil {
				response.Header.ErrorStr = fmt.Sprintf("unmarshal err %v\n", err)
			}
			//response.Header.Status = http.StatusOK
			break
		} else if err == nats.ErrTimeout {
			retries = retries - 1
			if retries > 0 {
				time.After(500 * time.Millisecond)
				continue
			}
			response.Header.Status = http.StatusRequestTimeout
		} else {
			response.Header.Status = http.StatusNotFound
			response.Header.ErrorStr = fmt.Sprintf("nextmsg err %v\n", err)
		}
		break
	}
	err = s.Unsubscribe()
	if err != nil {
		response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n", err)
	}

	return response

}

func Post(server string, body []byte, dopts Dopts, token APIToken) *NATSResponse {

	dflags := make(map[string]interface{})
	if dopts["entityAccess"] != nil {
		dflags["entityAccess"] = dopts["entityAccess"].(string)
	}
	if dopts["withHeader"] != nil {
		dflags["withHeader"] = dopts["withHeader"].(string)
	}
	if dopts["secureHeader"] != nil {
		dflags["secureHeader"] = dopts["secureHeader"].(string)
	}
	if dopts["domain"] != nil {
		dflags["domain"] = dopts["domain"].(string)
	}
	if dopts["entity"] != nil {
		dflags["entity"] = dopts["entity"].(string)
	}
	if dopts["rdid"] != nil {
		dflags["rdid"] = dopts["rdid"].(string)
	}
	if dopts["aspect"] != nil {
		dflags["aspect"] = dopts["aspect"].(string)
	}
	if dopts["expiry"] != nil {
		dflags["expiry"] = dopts["expiry"].(string)
	}
	if dopts["Content-Type"] != nil {
		dflags["Content-Type"] = dopts["Content-Type"].(string)
	}

	sessKey := GetSessionKey(token.Token)
	if sessKey == nil {
		return SessionKeyNilError()
	}

	mode := "POST"
	dhdr := NATSReqHeader{
		Mode: mode,
		Path: fmt.Sprintf("/%v/%v/%v/%v", dflags["domain"],
			dflags["entity"], dflags["rdid"], dflags["aspect"]),
		Flags:         dflags,
		Authorization: token.Token,
		SessPubkey:    sessKey.GetPubKey().ToB64(), // set public key to encrypt further server requests

	}

	replyTo := libnc.NewRespInbox()
	dhdr.ReplyTo = replyTo

	drec := &NATSRequest{
		Header: dhdr,
		Body:   body,
	}

	response := &NATSResponse{}

	payload, err := json.Marshal(drec)
	//fmt.Printf("POST header %v body %v\n",dhdr,string(body))
	encrypted := dpEncrypt(payload)

	s, err := libnc.SubscribeSync(replyTo)
	libnc.Flush()

	_, err = libnc.Request(server, encrypted, 10*time.Second)
	if err != nil {
		response.Header.Status = http.StatusBadGateway
		if libnc.LastError() != nil {
			log.Printf("%v for request", libnc.LastError())
			response.Header.ErrorStr = fmt.Sprintf("%v for request", libnc.LastError())
		}
		log.Printf("%v for request", err)
		response.Header.ErrorStr = fmt.Sprintf("%v for request", err)
		response.Header.Status = http.StatusGatewayTimeout
		return response
	}

	retries := 50
	waitMulti := 100 * time.Millisecond // set timeout to one tenth second
	// problem we can't predict how long the server takes to respond
	for {
		//msg, err := s.NextMsg(1000 * time.Millisecond) // wait up to 1 second
		msg, err := s.NextMsg(waitMulti) // wait up to waitMulti second
		if err == nil && len(msg.Data) != 0 {
			sessKey := GetSessionKey(token.Token)
			if sessKey == nil {
				response.Header.Status = http.StatusNetworkAuthenticationRequired
				response.Header.ErrorStr = "session key expired"
				return response
			}
			rmsg := _Decrypt(msg.Data, sessKey)
			err = json.Unmarshal(rmsg, response)
			if err != nil {
				response.Header.ErrorStr = fmt.Sprintf("unmarshal err %v\n", err)
			} // TODO: fix server response
			if response.Header.Status == 0 { // server returning improper status in some cases
				response.Header.Status = http.StatusNotAcceptable
			}
		} else if err == nats.ErrTimeout { // try again
			retries = retries - 1
			if retries > 0 {
				waitMulti = waitMulti * 2 // double the wait time each loop
				//fmt.Printf("wait %v\n",waitMulti)
				time.After(1000 * time.Millisecond) // wait one second before retry
				continue
			}
			response.Header.Status = http.StatusRequestTimeout
		} else { // we're out of here
			response.Header.ErrorStr = fmt.Sprintf("response err %v", err)
			response.Header.Status = http.StatusNotFound
		}
		break
	}
	err = s.Unsubscribe()
	if err != nil {
		response.Header.ErrorStr = fmt.Sprintf("unsub err %v\n", err)
	}

	return response
}

// ///////////////////////////////// SECURE CHANNELS //////////////
// //
func InitChannel(server, ch string, token APIToken, create bool) (string, error) {
	///////////////////////////////////////
	// setup 'ch' secure channel
	// token = owner of channel
	// register channel entity
	// register RDID
	pc, status := EntityRetrieve(server, ch, token)
	if status != http.StatusOK {
		if create {
			pc, status = EntityRegister(server, ch, token,
				"", "", server, []byte(""), []byte(ch))
			fmt.Printf("%v GrpEntity passCode %v status %v\n", ch, pc, status)
			if status == http.StatusRequestTimeout { // retry
				time.After(1 * time.Second)
				pc, status = EntityRegister(server, ch, token,
					"", "", server, []byte(""), []byte(ch))
			}
			if status != http.StatusOK {
				return "", fmt.Errorf("Channel %v entity init err %v\n", ch, status)
			}
		}
	}

	//pcode := json.Unmarshal(pc,)
	// register channel RDID for controlled access
	scRDID, status := RelationRetrieve(server, ch, token)
	if status != http.StatusOK {
		if create {
			scRDID, status = RelationRegister(server, ch, token, "write")
			if status == http.StatusRequestTimeout { // retry
				time.After(1 * time.Second)
				scRDID, status = RelationRegister(server, ch, token, "write")
			}
			if status != http.StatusOK {
				return "", fmt.Errorf("Channel %v RDID init err %v\n", ch, status)
			}
		}
	}
	libnc.Flush()
	ichannel := libnc.NewRespInbox() // create unique response message key
	postData := `{ "data" : { "entity" : "` + ch + `", "innerchannel" : "` + ichannel + `" }}`

	dflags := make(map[string]interface{})
	SetDomain(dflags, "SecureChannel")
	SetEntity(dflags, ch)
	SetRDID(dflags, scRDID)
	SetAspect(dflags, "entity")
	SetTag(dflags, "data")
	SetTimestamp(dflags, "latest")
	fmt.Printf("SC ch %v RDID %v token %v\n", ch, scRDID, token)
	rsp := Get(server, dflags, token)
	libnc.Flush()
	for {
		if rsp.Header.Status == http.StatusRequestTimeout { // retry
			rsp = Get(server, dflags, token)
			fmt.Printf("Channel %v loop status = %v\n", ch, rsp.Header.Status)
			if rsp.Header.Status == http.StatusOK {
				if string(rsp.Response) == "" {
					rsp.Header.Status = http.StatusNotFound
					break
				}
			}
		} else {
			break
		}
	}
	fmt.Printf("Channel %v after lookup status = %v\n", ch, rsp.Header.Status)
	if string(rsp.Response) == "" {
		fmt.Printf("after lookup res %v\n", rsp.Response)
		rsp.Header.Status = http.StatusNotFound
	}
	if rsp.Header.Status != http.StatusOK {
		if create {
			fmt.Printf("create ch %v\n", ch)
			rsp = Post(server, []byte(postData), dflags, token)
			if rsp.Header.Status != http.StatusOK {
				return "", fmt.Errorf("Channel %v init err %v\n", ch, rsp.Header.Status)
			}
		}
	}
	if rsp.Header.Status != http.StatusOK && rsp.Header.Status != 0 {
		fmt.Printf("cannot store channel %v err %v\n", ch, rsp.Header.Status)
	}
	libnc.Flush()
	fmt.Printf("Init ch %v err %v\n", ch, rsp.Header.Status)
	return scRDID, nil
}

func SetupSecureChannels(server string, channelList []string, token APIToken, create bool) map[string]string {
	scRDID := make(map[string]string, len(channelList))
	for _, ch := range channelList {
		rdid, _ := InitChannel(server, ch, token, create)
		scRDID[ch] = rdid
	}
	return scRDID
}

func SCCheckAndResolve(server, channel string, token APIToken, rdid string) (string, error) {
	// get recvd message replyTo message

	dflags := make(map[string]interface{})
	SetDomain(dflags, "SecureChannel")
	SetEntity(dflags, channel)
	SetRDID(dflags, rdid)
	SetAspect(dflags, "entity")
	SetTag(dflags, "data")
	SetTimestamp(dflags, "latest")
	rsp := Get(server, dflags, token)
	for {
		fmt.Printf("returned GET status %v\n", rsp.Header.Status)
		if rsp.Header.Status == http.StatusRequestTimeout { // retry for timeout
			rsp = Get(server, dflags, token)
		} else {
			break
		}
	}
	libnc.Flush()
	if rsp.Header.Status != http.StatusOK {
		return "", fmt.Errorf("invalid access %v", rsp.Header.Status)
	}

	type entityInfo struct {
	}

	type datarec struct {
		Entity       string `json:"entity"`
		InnerChannel string `json:"innerchannel"`
	}

	type grspHeaderResults struct {
		Data datarec `json:"data"`
	}

	type qrspHeader struct {
		DocId      string              `json:"docId"`
		DocVersion string              `json:"docVersion"`
		Created    int64               `json:"created"`
		Results    []grspHeaderResults `json:"results"`
	}
	type queryResponse struct {
		Docs []qrspHeader `json:"docs"`
	}
	var scInnerChannel string
	if rsp.Header.Status == http.StatusOK {
		rspData := queryResponse{}
		err := json.Unmarshal([]byte(rsp.Response), &rspData)
		if err != nil {
			return "", fmt.Errorf("unmarshall err %v", err)
		}
		scInnerChannel = rspData.Docs[0].Results[0].Data.InnerChannel
	} else {
		scInnerChannel = ""
	}
	return scInnerChannel, nil
}

func processChannelReceivedMsg(msg *nats.Msg) ([]byte, error) {

	return msg.Data, nil
}

func SecureChannelQueueSubscribe(server, channel, queue string, token APIToken, rdid string, cb nats.MsgHandler) (*nats.Subscription, error) {
	log.Printf("Connecting secure channel %s\n", channel)
	var err error
	var ichannel string
	if ichannel, err = SCCheckAndResolve(server, channel, token, rdid); err != nil {
		log.Printf("Error: no access %s\n", err)
		return nil, err
	}
	// Subscribe to innerchannel topic
	sub, err := libnc.QueueSubscribe(ichannel, queue, cb) //func(m *nats.Msg) {

	return sub, err

}

func SecureChannelPublish(msg []byte, server string, channel string,
	token APIToken, rdid string, expireSecs int64) error {
	log.Printf("Publishing secure channel %s\n", channel)
	var err error
	var ichannel string
	if ichannel, err = SCCheckAndResolve(server, channel, token, rdid); err != nil {
		log.Printf("Error: %s\n", err)
		return err
	}
	receiveTopic := libnc.NewRespInbox() // publish to temp uniquely named receive topic
	m := &nats.Msg{}
	m.Subject = receiveTopic
	m.Data = msg
	if err := libnc.PublishMsg(m); err != nil {
		log.Printf("Error: %s\n", err)
		return err
	}
	msgKey := libnc.NewRespInbox()     // create unique message key
	m.Subject = ichannel + ":MsgAvail" // publish to MsgAvail topic
	m.Data = []byte(msgKey)            // set message Data to temp uniquely named receive topic key
	// by which to lookup in D-DDN subscriber received MsgAvail
	if err := libnc.PublishMsg(m); err != nil { // publish message to channel MsgAvail Topic
		log.Printf("Error: %s\n", err)
		return err
	}
	// POST to channel MsgAvail entity entry for subscriber later lookup
	payload := `{"receive_topic" : "` + receiveTopic + `"}`
	dflags := make(map[string]interface{})
	SetDomain(dflags, "SecureChannel")
	SetEntity(dflags, channel)
	SetRDID(dflags, rdid)
	SetAspect(dflags, "messages")
	SetExpiry(dflags, strconv.FormatInt(expireSecs, 10))
	rsp := Post(server, []byte(payload), dflags, token)
	if rsp.Header.Status != http.StatusOK {
		err := fmt.Errorf("error %v\n", rsp.Header.Status)
		return err
	}

	return nil

}

func SecureChannelRequest(server, subj, rdid string, token APIToken, data []byte, timeout time.Duration) (*nats.Msg, error) {
	log.Printf("Requesting secure channel %s\n", subj)
	var err error
	var ichannel string
	if ichannel, err = SCCheckAndResolve(server, subj, token, rdid); err != nil {
		log.Printf("Error: %s\n", err)
		return nil, err
	}
	log.Printf("request on innerchannel %v\n", ichannel)
	m, err := libnc.Request(ichannel, data, timeout)
	libnc.Flush()
	return m, err

}

func ConnectAPI(url, srvtopic string) *nats.Conn {

	opts := []nats.Option{nats.Name("NATS Client Lib")}
	opts = setupConnOptions(opts)

	// Connect to NATS
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		log.Fatal(err)
	}

	libnc = nc
	/*ServerToken = getServerPubKey(DefaultServer)
	ServerKey = genKey()
	ServerKey.GetPubKey().FromB64(ServerToken.SPubKey)


	*/
	return libnc

}

func setupConnOptions(opts []nats.Option) []nats.Option {
	totalWait := 10 * time.Minute
	reconnectDelay := time.Second

	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		log.Printf("Disconnected due to: %s, will attempt reconnects for %.0fm", err, totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		log.Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		log.Fatalf("Exiting: %v", nc.LastError())
	}))
	return opts
}
