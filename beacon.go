package nistbeacon

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

/*
An overview is at <http://www.nist.gov/itl/csd/ct/nist_beacon.cfm> and while
the REST API is reliably available (in my experience) the content at
<https://beacon.nist.gov/home> is not, so I'll replicate the data here from
when it was available:

  This prototype implementation generates full-entropy bit-strings and posts
  them in blocks of 512 bits every 60 seconds. Each such value is
  sequence-numbered, time-stamped and signed, and includes the hash of the
  previous value to chain the sequence of values together and prevent even the
  source to retroactively change an output package without being detected.

  Currently implemented calls are listed below. Users submitting a request need
  to provide the record generation time in POSIX format (number of seconds
  since midnight UTC, January 1, 1970 (see
  http://en.wikipedia.org/wiki/Unix_time for more information and
  http://www.epochconverter.com for an online timestamp converter.)

  Current Record (or next closest):
    https://beacon.nist.gov/rest/record/<timestamp>
  Previous Record:
    https://beacon.nist.gov/rest/record/previous/<timestamp>
  Next Record:
    https://beacon.nist.gov/rest/record/next/<timestamp>
  Last Record:
    https://beacon.nist.gov/rest/record/last
  Start Chain Record:
    https://beacon.nist.gov/rest/record/start-chain/<timestamp>

  If a request for a next or previous record results in no record found, a 404
  response is returned.

  Schema

  The data source schema for the NIST Beacon REST API described above can be
  viewed by clicking here (<https://beacon.nist.gov/record/0.1/beacon-0.1.0.xsd>).

  */

  //nist public key
const beaconPubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryY9m2YHOui12tk93ntMZAL2uvlXr7j
Taxx5WJ1PM6SJllJ3IopuwUQGLxUEDNinFWE2xlF5sayoR+CRZGDG6Hjtw2fBRcsQKiIpaws6Cd
usRaRMM7Wjajm3vk96gD7Mwcqo+uxuq9186UeNPLeAxMmFlcQcSD4pJgKrZKgHtOk0/t2kz9cgJ
343aN0LuV7w91LvfXwdeCtcHM4nyt3gV+UyxAe6wPoOSsM6Px/YLHWqAqXMfSgEQrd920LyNb+V
gNcPyqhLySDyfcUNtr1BS09nTcw1CaE6sTmtSNLiJCuWzhlzsjcFh5uMoElAaFzN1ilWCRk/02/
B/SWYPGxWIQIDAQAB
-----END PUBLIC KEY-----
`

// beaconCertificate gives us the beacon certificate as a Golang object; it
// always succeeds, because the beacon is a const encoded herein, so a failure
// is panic-worthy.
func beaconCertificate() (*rsa.PublicKey, error) {
	pemBlock, remainder := pem.Decode([]byte(beaconPubKey))
	if len(remainder) > 0 {
		return nil, errors.New("invalid pem")
	}
	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

func fetchRecord(timestamp int64) ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("https://beacon.nist.gov/rest/record/%d", timestamp))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}

type BeaconData struct {
	XMLName             xml.Name `xml:"record"`
	Version             string   `xml:"version"`
	Frequency           uint32   `xml:"frequency"`
	TimeStamp           uint64   `xml:"timeStamp"`
	SeedValue           string   `xml:"seedValue"`
	PreviousOutputValue string   `xml:"previousOutputValue"`
	SignatureValue      string   `xml:"signatureValue"`
	OutputValue         string   `xml:"outputValue"`
	StatusCode          uint32   `xml:"statusCode"`
}

func (d *BeaconData) VerificationData() (signed, signature []byte, err error) {
	signature, err = hex.DecodeString(d.SignatureValue)
	if err != nil {
		return nil, nil, err
	}
	/*
		http://hackaday.com/2014/12/19/nist-randomness-beacon/
		## Create a bytewise reversed version of the listed signature
		## This is necessary b/c Beacon signs with Microsoft CryptoAPI which outputs
		## the signature as little-endian instead of big-endian like many other tools
		## This may change (personal communication) in a future revision of the Beacon
	*/
	sigLimit := len(signature) - 1
	for i := 0; i <= sigLimit/2; i++ {
		signature[i], signature[sigLimit-i] = signature[sigLimit-i], signature[i]
	}

	b := new(bytes.Buffer)
	//b.Grow(200)
	_, _ = b.WriteString(d.Version)
	binary.Write(b, binary.BigEndian, d.Frequency)
	binary.Write(b, binary.BigEndian, d.TimeStamp)
	seed, err := hex.DecodeString(d.SeedValue)
	if err != nil {
		return nil, nil, err
	}
	_, _ = b.Write(seed)
	prev, err := hex.DecodeString(d.PreviousOutputValue)
	if err != nil {
		return nil, nil, err
	}
	_, _ = b.Write(prev)
	binary.Write(b, binary.BigEndian, d.StatusCode)

	return b.Bytes(), signature, nil
}

type beaconMaker struct {
	Debug     bool
	DebugFH   io.Writer
	verifyKey *rsa.PublicKey
}

func NewBeaconMaker() (*beaconMaker, error) {
	key, err := beaconCertificate()
	if err != nil{
		return nil, err
	}
	return &beaconMaker{
		verifyKey: key,
	}, nil
}

func (m *beaconMaker) DebugCertificate() {
	//m.Debugf("certificate: %#v\n", m.verifyCert)
}

func (m *beaconMaker) ValidateSignature(signed, signature []byte) error {

	hash := sha512.Sum512(signed)

	return rsa.VerifyPKCS1v15(m.verifyKey, crypto.SHA512, hash[:], signature)

}

func (m *beaconMaker) NewByXMLBytes(rawxml []byte) (*BeaconData, error) {
	var bd *BeaconData
	err := xml.Unmarshal(rawxml, &bd)
	if err != nil {
		return nil, fmt.Errorf("decoding beacon data from XML failed: %s\n", err)
	}
	verifiable, signature, err := bd.VerificationData()
	if err != nil {
		return bd, fmt.Errorf("preparing beacon data for signature verification failed: %s\n", err)
	}
	if len(verifiable) == 0 {
		return nil, errors.New("beacon signature verifiable form of length 0")
	}
	if len(signature) == 0 {
		return nil, errors.New("beacon signature of length 0")
	}
	err = m.ValidateSignature(verifiable, signature)
	if err != nil {
		return bd, fmt.Errorf("failed to verify beacon signature: %s\n", err)
	}
	return bd, nil
}

func (m *beaconMaker) NewByTimestamp(ts int64) (*BeaconData, error) {
	if ts%60 != 0 {
		ts -= ts % 60
	}
	rawBeaconData, err := fetchRecord(ts)
	if err != nil {
		return nil, fmt.Errorf("fetching beacon data failed: %s\n", err)
	}

	return m.NewByXMLBytes(rawBeaconData)
}

var beaconCmdlineFlags struct {
	debug bool
}

func GetBeaconData() ([]byte, error) {

	maker, err := NewBeaconMaker()
	if err != nil {
		return nil, err
	}
	timeStamp := time.Now().Unix()

	beacon, err := maker.NewByTimestamp(timeStamp)
	if err != nil {
		return nil, err
	}

	seed, err := hex.DecodeString(beacon.SeedValue)
	if err != nil {
		return nil, err
	}
	return seed, nil
}
