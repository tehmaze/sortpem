package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	allFlag     = flag.Bool("a", false, "Output all blocks, not only the ones matching -t")
	caFlag      = flag.String("ca", "", "CA file")
	countFlag   = flag.Bool("c", false, "Count blocks")
	dumpFlag    = flag.Bool("d", false, "Dump text output of decoded PEM block")
	typesFlag   regexps
	outputFlag  = flag.String("o", "", "Print the output to a file in stead of standard output")
	presetFlag  = flag.String("p", "", `Preset (use "list" for an overview)`)
	reverseFlag = flag.Bool("r", false, "Reverse sort")
	rootFlag    = flag.Bool("root", false, "Include root certificate")
	stableFlag  = flag.Bool("s", false, "Stable sort")
	uniqueFlag  = flag.Bool("u", false, "Unique blocks")
	debugFlag   = flag.Bool("D", false, "Enable debug logging")
)

type regexps []*regexp.Regexp

func (res *regexps) Index(s string) int {
	if res != nil && len(*res) > 0 {
		for i, r := range *res {
			if r.MatchString(s) {
				return i
			}
		}
	}
	return -1
}

func (res *regexps) MatchString(s string) bool {
	if res == nil || len(*res) == 0 {
		return true
	}
	for _, re := range *res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (res *regexps) String() string {
	s := make([]string, len(*res))
	for i, r := range *res {
		s[i] = r.String()
	}
	return strings.Join(s, ",")
}

func (res *regexps) Set(value string) error {
	r, err := regexp.Compile(value)
	if err != nil {
		return err
	}
	*res = append(*res, r)
	return nil
}

// PEM block types.
const (
	certificate               = "CERTIFICATE"
	certificateRequest        = "CERTIFICATE REQUEST"
	certificateRevocationList = "X509 CRL"
	dhParameters              = "DH PARAMETERS"
	openVPNStaticKey          = "OpenVPN Static key"
	publicKey                 = "PUBLIC KEY"
	privateKey                = "PRIVATE KEY"
	rsaPublicKey              = "RSA " + publicKey
	rsaPrivateKey             = "RSA " + privateKey
	ecPrivateKey              = "EC " + privateKey
	x509PrivateKey            = `(?:RSA |EC |)` + privateKey
	opensshPrivateKey         = "OPENSSH " + privateKey
)

// PEM block type regular expressions.
var (
	oneCertificate               = regexp.MustCompile(`^` + certificate + `$`)
	oneCertificateRequest        = regexp.MustCompile(`^` + certificateRequest + `$`)
	oneCertificateRevocationList = regexp.MustCompile(`^` + certificateRevocationList + `$`)
	anyPrivateKey                = regexp.MustCompile(privateKey + `$`)
	oneX509PrivateKey            = regexp.MustCompile(`^` + x509PrivateKey + `$`)
	oneRSAPrivateKey             = regexp.MustCompile(`^` + rsaPrivateKey + `$`)
	oneOpenVPNStaticKey          = regexp.MustCompile(`^` + openVPNStaticKey)
	oneOpenSSHPrivateKey         = regexp.MustCompile(`^` + opensshPrivateKey + `$`)
)

var (
	// roots are our trusted roots, either coming from system or -ca file
	roots *CertPool

	// cache of already-parsed certificate blocks
	cache = map[string]*x509.Certificate{}

	// maxWidth is our maximum terminal width
	maxWidth int

	// writers for debugf(), warnf() and fatalf()
	debugWriter = os.Stderr
	errorWriter = os.Stderr

	// presets for -p
	presets = []preset{
		{Name: "crl", Filter: regexps{oneCertificateRevocationList}},
		{Name: "crt", Root: true, Filter: regexps{oneCertificate}},
		{Name: "csr", Filter: regexps{oneCertificateRequest}},
		{Name: "key", Filter: regexps{oneX509PrivateKey}},
		{Name: "nginx", Filter: regexps{oneCertificate, oneX509PrivateKey}},
		{Name: "haproxy", Filter: regexps{oneCertificate, oneX509PrivateKey}, Root: true},
		{Name: "openvpn", Filter: regexps{oneCertificate, oneX509PrivateKey, oneOpenVPNStaticKey}},
		{Name: "ssh", Filter: regexps{oneOpenSSHPrivateKey}},
	}
)

// preset is a collection of flag defaults.
type preset struct {
	Name    string
	Reverse bool
	Root    bool
	Stable  bool
	Unique  bool
	Filter  regexps
}

func (p preset) Apply() {
	debugf("applying preset: %q", p)
	if p.Reverse {
		*reverseFlag = true
	}
	if p.Root {
		*rootFlag = true
	}
	if p.Stable {
		*stableFlag = true
	}
	if p.Unique {
		*uniqueFlag = true
	}
	if len(p.Filter) > 0 {
		typesFlag = p.Filter
	}
}

func (p preset) String() string {
	var s []string
	for _, r := range p.Filter {
		s = append(s, fmt.Sprintf(`-t %q`, r))
	}
	if p.Reverse {
		s = append(s, "-r")
	}
	if p.Root {
		s = append(s, "-root")
	}
	if p.Stable {
		s = append(s, "-s")
	}
	if p.Unique {
		s = append(s, "-u")
	}
	return strings.Join(s, " ")
}

func main() {
	flag.Var(&typesFlag, "t", "Type of block order and filter (regular expression(s))")
	flag.Usage = usage
	flag.Parse()

	// resolve terminal width asap
	maxWidth = terminalWidth() - 1

	switch *presetFlag {
	case "":
	case "list":
		listPresets()
		os.Exit(0)
	default:
		var (
			p  preset
			ok bool
		)
		for _, p = range presets {
			if ok = p.Name == *presetFlag; ok {
				break
			}
		}
		if !ok {
			fatalf(`preset %q is unknown, use "list" for a list`)
		}
		p.Apply()
	}

	var err error
	if roots, err = readRoots(); err != nil {
		fatalf("error loading system certificates: %v", err)
	}

	data, err := readInput(flag.Args())
	if err != nil {
		fatalf("%v", err)
	}

	blocks := decodeAll(data)
	if len(blocks) == 0 {
		return
	}

	if *rootFlag {
		blocks = includeRoot(blocks)
	} else {
		blocks = excludeRoots(blocks)
	}

	if *countFlag {
		count := map[string]int{}
		for _, block := range blocks {
			count[block.Type]++
		}
		for kind, n := range count {
			fmt.Printf("%8d %s\n", n, kind)
		}
		return
	}

	if *stableFlag {
		sort.Stable(blocks)
	} else {
		sort.Sort(blocks)
	}

	var (
		output io.WriteCloser
		name   string
	)
	if output, name, err = openOutput(); err != nil {
		fatalf("error opening %s: %v", name, err)
	}
	defer output.Close()

	for _, block := range blocks {
		if *dumpFlag {
			if err = dumpText(output, block); err != nil {
				warnf("failed to dump %s block: %v", block.Type, err)
			}
		}
		if err = pem.Encode(output, block); err != nil {
			fatalf("error writing to %s: %v", name, err)
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Syntax:\n  sortpem [<options>] [<input(s)>]\n\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nPresets:")
	listPresets()
}

func listPresets() {
	for _, p := range presets {
		fmt.Fprintf(os.Stderr, "  %-8s %s\n", p.Name, p)
	}
}

func readRoots() (pool *CertPool, err error) {
	if *caFlag == "" {
		if pool, err = SystemCertPool(); err == nil {
			debugf("roots: %d from system", len(pool.certs))
		}
		return
	}

	var pemBytes []byte
	if pemBytes, err = ioutil.ReadFile(*caFlag); err != nil {
		return nil, fmt.Errorf("error reading CA file %s: %v", *caFlag, err)
	}

	pool = NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		warnf("no PEM encoded certificates found in %s", *caFlag)
	}
	debugf("roots: %d from %s", len(pool.certs), *caFlag)

	return
}

func readInput(args []string) (data []byte, err error) {
	if len(args) == 0 {
		if data, err = ioutil.ReadAll(os.Stdin); err != nil {
			return nil, fmt.Errorf("error reading standard input: %v", err)
		}
		return
	}

	for _, name := range args {
		var (
			rc   io.ReadCloser
			part []byte
		)
		if name == "-" {
			name, rc = "standard input", os.Stdin
		} else {
			if rc, err = os.Open(name); err != nil {
				return nil, err
			}
		}
		if part, err = ioutil.ReadAll(rc); err != nil {
			rc.Close()
			return nil, fmt.Errorf("read %s: %v", name, err)
		} else if err = rc.Close(); err != nil {
			return nil, fmt.Errorf("close %s: %v", name, err)
		}
		data = append(data, part...)
	}

	return
}

func openOutput() (wc io.WriteCloser, name string, err error) {
	if *outputFlag == "" || *outputFlag == "-" {
		return os.Stdout, "standard output", nil
	}

	wc, err = os.Create(*outputFlag)
	name = *outputFlag
	return
}

func decodeAll(data []byte) (blocks pemBlocks) {
	var block *pem.Block
	for {
		if block, data = pem.Decode(data); block == nil {
			return
		}
		if *allFlag || typesFlag.MatchString(block.Type) {
			blocks = append(blocks, block)
		}
	}
}

var errCachedInvalid = errors.New("invalid certificate (cached)")

func decodeCertificate(pemCert []byte) (c *x509.Certificate, err error) {
	var ok bool
	if c, ok = cache[string(pemCert)]; ok {
		if c == nil {
			return nil, errCachedInvalid
		}
		return
	}

	c, err = x509.ParseCertificate(pemCert)
	cache[string(pemCert)] = c

	return
}

type pemBlocks []*pem.Block

func (blocks pemBlocks) Len() int { return len(blocks) }

func (blocks pemBlocks) Less(i, j int) bool {
	a, b := blocks[i], blocks[j]
	debugf("compare blocks: %q (%d) <=> %q (%d)", a.Type, i, b.Type, j)
	if a.Type == certificate {
		if b.Type == certificate {
			return compareCertificates(a.Bytes, b.Bytes) != *reverseFlag
		}
		return !*reverseFlag
	}

	ai, bi := typesFlag.Index(a.Type), typesFlag.Index(b.Type)
	if bi == -1 { // b's Type is not in -t
		return ai != -1
	}
	if bi == -1 { // a's Type is not in -t
		return false
	}
	if ai == bi { // a and b are of same type in -t
		return a.Type < b.Type
	}
	return ai < bi
}

func (blocks pemBlocks) Swap(i, j int) {
	blocks[i], blocks[j] = blocks[j], blocks[i]
}

func compareCertificates(i, j []byte) bool {
	var (
		a, b *x509.Certificate
		err  error
	)
	if a, err = decodeCertificate(i); err != nil {
		warnf("error parsing certificate: %v", err)
		return false
	}
	if b, err = decodeCertificate(j); err != nil {
		warnf("error parsing certificate: %v", err)
		return true
	}
	debugf("compare certificates: %q <=> %q", a.Subject, b.Subject)

	if a.AuthorityKeyId != nil {
		if bytes.Equal(a.AuthorityKeyId, b.SubjectKeyId) {
			// a is signed by b
			debugf("compare certificates: %q signed by %q", a.Subject, b.Subject)
			return true
		}
		if bytes.Equal(b.AuthorityKeyId, a.SubjectKeyId) {
			// b is signed by a
			debugf("compare certificates: %q has issued %q", a.Subject, b.Subject)
			return false
		}
	}

	switch {
	case isRoot(a):
		debugf("compare certificates: %q is root", a.Subject)
		return false
	case isRoot(b):
		debugf("compare certificates: %q is root", b.Subject)
		return true
	case isSelfSigned(a):
		debugf("compare certificates: %q is self-signed", a.Subject)
		return false
	case isSelfSigned(b):
		debugf("compare certificates: %q is self-signed", b.Subject)
		return true
	}

	return false // don't know!
}

// includeRoot attempts to resolve root certificates for CERTIFICATE types in
// blocks; it also removes any CERTIFICATE blocks that fail to decode
func includeRoot(blocks []*pem.Block) []*pem.Block {
	debugf("including root certificate for %d block(s)", len(blocks))

	var (
		found bool
		certs = make([]*x509.Certificate, 0, len(blocks))
	)
	for i, block := range blocks {
		if block.Type == certificate {
			c, err := decodeCertificate(block.Bytes)
			if err != nil {
				warnf("error parsing certificate: %v", err)
				// found a broken certificate block, resume from start
				return includeRoot(append(blocks[:i], blocks[i+1:]...))
			} else if found = isRoot(c); found {
				// already a root certificate, nothing to do here
				return blocks
			}
			certs = append(certs, c)
		}
	}

	// now, for the parsed certificates, find roots
	for _, cert := range certs {
		if parents, _, err := roots.findVerifiedParents(cert); err != nil {
			warnf("error finding root certificate for %q: %v", cert.Subject, err)
		} else if len(parents) > 0 {
			debugf("including %d certificate(s) from system roots", len(parents))
			for _, root := range parents {
				blocks = append(blocks, &pem.Block{
					Type:  certificate,
					Bytes: roots.certs[root].Raw,
				})
			}
		}
	}

	return blocks
}

// excludeRoots attempts to remove root certificates for CERTIFICATE types in
// blocks; it also removes any CERTIFICATE blocks that fail to decode
func excludeRoots(blocks []*pem.Block) []*pem.Block {
	debugf("filtering out root certificates in %d block(s)", len(blocks))

	for i, block := range blocks {
		if block.Type == certificate {
			c, err := decodeCertificate(block.Bytes)
			if err != nil {
				warnf("error parsing certificate: %v", err)
			}
			if err != nil || isRoot(c) {
				// remove certificates with errors and root certificates and try again
				return excludeRoots(append(blocks[:i], blocks[i+1:]...))
			}
		}
	}

	return blocks
}

func isRoot(c *x509.Certificate) bool {
	if roots != nil && roots.contains(c) {
		debugf("root certificate %q (in trusted roots)", c.Subject)
		return true
	}
	if isSelfSigned(c) {
		debugf("root certificate %q (self-signed)", c.Subject)
		return true
	}
	return false
}

func isSelfSigned(c *x509.Certificate) bool {
	if c.AuthorityKeyId != nil {
		return bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId)
	}
	return bytes.Equal(c.RawSubject, c.RawIssuer)
}

func debugf(format string, v ...interface{}) {
	if !*debugFlag {
		return
	}
	fmt.Fprintf(debugWriter, "debug: "+strings.TrimRight(format, "\r\n")+"\n", v...)
}

func warnf(format string, v ...interface{}) {
	fmt.Fprintf(errorWriter, "warning: "+strings.TrimRight(format, "\r\n")+"\n", v...)
}

func fatalf(format string, v ...interface{}) {
	fmt.Fprintf(errorWriter, "fatal: "+strings.TrimRight(format, "\r\n")+"\n", v...)
	os.Exit(1)
}
