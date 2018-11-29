package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
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

/*
func (res *regexps) Less(a, b string) bool {
	if res == nil || len(*res) == 0 {
		return false
	}
	i, j := res.Index(a), res.Index(b)
	debugf("types less(%q, %q): %d <=> %d", a, b, i, j)
	if j == -1 {
		return i != -1
	}
	if i == -1 {
		return false
	}
	return i < j
}
*/

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

const (
	certificate        = "CERTIFICATE"
	certificateRequest = "CERTIFICATE REQUEST"
	publicKey          = "PUBLIC KEY"
	privateKey         = "PRIVATE KEY"
	rsaPublicKey       = "RSA " + publicKey
	rsaPrivateKey      = "RSA " + privateKey
	ecPrivateKey       = "EC " + privateKey
)

var (
	// regexps
	oneCertificate   = regexp.MustCompile(`^` + certificate + `$`)
	anyPrivateKey    = regexp.MustCompile(privateKey + `$`)
	oneRSAPrivateKey = regexp.MustCompile(`^` + rsaPrivateKey + `$`)
)

var (
	roots   *CertPool
	cache   = map[string]*x509.Certificate{}
	presets = []preset{
		{Name: "certs", Root: true, Filter: regexps{oneCertificate}},
		{Name: "keys", Filter: regexps{anyPrivateKey}},
		{Name: "nginx", Filter: regexps{oneCertificate, anyPrivateKey}},
		{Name: "haproxy", Filter: regexps{oneCertificate, anyPrivateKey}, Root: true},
	}
)

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
		s = append(s, "-R")
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

	data, err := readInput()
	if err != nil {
		fatalf("%v", err)
	}

	blocks, err := decodeAll(data)
	if err != nil {
		fatalf("error decoding blocks: %v", err)
	}
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
		sort.SliceStable(blocks, compareBlock(blocks))
	} else {
		sort.Slice(blocks, compareBlock(blocks))
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

func readInput() (data []byte, err error) {
	if flag.NArg() == 0 {
		if data, err = ioutil.ReadAll(os.Stdin); err != nil {
			return nil, fmt.Errorf("error reading standard input: %v", err)
		}
		return
	}

	for _, name := range flag.Args() {
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
	if *outputFlag == "" {
		return os.Stdout, "standard output", nil
	}

	wc, err = os.Create(*outputFlag)
	name = *outputFlag
	return
}

func decodeAll(data []byte) (blocks []*pem.Block, err error) {
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

func decodeCertificate(pemCert []byte) (c *x509.Certificate, err error) {
	var ok bool
	if c, ok = cache[string(pemCert)]; ok {
		return
	}

	if c, err = x509.ParseCertificate(pemCert); err == nil {
		cache[string(pemCert)] = c
	}

	return
}

func compareBlock(blocks []*pem.Block) func(int, int) bool {
	return func(i, j int) bool {
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
				return includeRoot(append(blocks[:i], blocks[i+1:]...))
			} else if found = isRoot(c); found {
				return blocks
			}
			certs = append(certs, c)
		}
	}

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

func excludeRoots(blocks []*pem.Block) []*pem.Block {
	debugf("filtering out root certificates in %d block(s)", len(blocks))

	for i, block := range blocks {
		if block.Type == certificate {
			c, err := decodeCertificate(block.Bytes)
			if err != nil {
				warnf("error parsing certificate: %v", err)
				return excludeRoots(append(blocks[:i], blocks[i+1:]...))
			} else if isRoot(c) {
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
	fmt.Fprintf(os.Stderr, "debug: "+strings.TrimRight(format, "\r\n")+"\n", v...)
}

func warnf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, "warning: "+strings.TrimRight(format, "\r\n")+"\n", v...)
}

func fatalf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+strings.TrimRight(format, "\r\n")+"\n", v...)
	os.Exit(1)
}
