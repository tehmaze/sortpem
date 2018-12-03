package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/tehmaze/sortpem"
)

// Build information
var (
	Version   = "(development version)"
	BuildDate = time.Now().UTC().Format("2 January 2006, 15:04:05")
	BuildHash = "HEAD"
)

// Command flags
var (
	allFlag     = flag.Bool("a", false, "Output all blocks, not only the ones matching -t")
	caFlag      = flag.String("ca", "", "CA file")
	countFlag   = flag.Bool("c", false, "Count blocks")
	dumpFlag    = flag.Bool("d", false, "Dump text output of decoded PEM block")
	typesFlag   = append(keys, certificate)
	outputFlag  = flag.String("o", "", "Print the output to a file in stead of standard output")
	presetFlag  = flag.String("p", "", `Preset (use "list" for an overview)`)
	reverseFlag = flag.Bool("r", false, "Reverse sort")
	rootFlag    = flag.Bool("root", false, "Include root certificate")
	stableFlag  = flag.Bool("s", false, "Stable sort")
	uniqueFlag  = flag.Bool("u", false, "Unique blocks")
	debugFlag   = flag.Bool("D", false, "Enable debug logging")
	versioFlag  = flag.Bool("v", false, "Show version and exit")
)

// Globals
var (
	// roots are our trusted roots, either coming from system or -ca file
	roots *sortpem.CertPool

	// cache of already-parsed certificate blocks
	cache = map[string]*x509.Certificate{}

	// maxWidth is our maximum terminal width
	maxWidth int

	// writers for debugf(), warnf() and fatalf()
	debugWriter = os.Stderr
	errorWriter = os.Stderr

	// types
	keys         = stringList{privateKey, rsaPrivateKey, ecPrivateKey}
	defaultTypes = append(keys, certificate)

	// presets for -p
	presets = []preset{
		{Name: "crl", Filter: stringList{certificateRevocationList}},
		{Name: "crt", Root: true, Filter: stringList{certificate}},
		{Name: "csr", Filter: stringList{certificateRequest}},
		{Name: "key", Filter: keys},
		{Name: "nginx", Filter: defaultTypes},
		{Name: "haproxy", Filter: defaultTypes, Root: true},
		{Name: "openvpn", Filter: append(defaultTypes, openVPNStaticKeyV1)},
		{Name: "ssh", Filter: stringList{opensshPrivateKey}},
	}
)

type stringList []string

func (s stringList) Contains(value string) bool {
	for _, other := range s {
		if other == value {
			return true
		}
	}
	return false
}

func (s *stringList) Set(values string) error {
	for _, value := range strings.Split(values, ",") {
		if value = strings.TrimSpace(value); value != "" {
			*s = append(*s, value)
		}
	}
	return nil
}

func (s stringList) String() string {
	return strings.Join(s, ",")
}

var _ flag.Value = (*stringList)(nil)

// preset is a collection of flag defaults.
type preset struct {
	Name    string
	Reverse bool
	Root    bool
	Stable  bool
	Unique  bool
	Filter  stringList
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
	if len(p.Filter) > 0 {
		s = append(s, fmt.Sprintf(`-t %q`, strings.Join(p.Filter, ",")))
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
	flag.Var(&typesFlag, "t", "Type order and filter (case sensitive, comma separated)")
	flag.Usage = usage
	flag.Parse()

	// version
	if *versioFlag {
		fmt.Println("sortpem", Version)
		if *debugFlag {
			fmt.Println("")
			fmt.Printf("Build date: %s\n", BuildDate)
			fmt.Printf("Build hash: %s\n", BuildHash)
			fmt.Printf("Go version: %s\n", runtime.Version())
		}
		return
	}

	// default types
	if len(typesFlag) == 0 {
		typesFlag = defaultTypes
	}

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

	sorter := sortpem.New(blocks)
	sorter.Order = typesFlag

	log.Printf("order: %#+v", sorter.Order)

	if *rootFlag {
		sorter.ResolveRoots()
	} else {
		sorter.ExcludeRoots()
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

	if *stableFlag && *reverseFlag {
		sort.Stable(sort.Reverse(sorter))
	} else if *stableFlag {
		sort.Stable(sorter)
	} else if *reverseFlag {
		sort.Sort(sort.Reverse(sorter))
	} else {
		sort.Sort(sorter)
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

func readRoots() (pool *sortpem.CertPool, err error) {
	if *caFlag == "" {
		if pool, err = sortpem.SystemCertPool(); err == nil {
			debugf("roots: %d from system", len(pool.Subjects()))
		}
		return
	}

	var pemBytes []byte
	if pemBytes, err = ioutil.ReadFile(*caFlag); err != nil {
		return nil, fmt.Errorf("error reading CA file %s: %v", *caFlag, err)
	}

	pool = sortpem.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		warnf("no PEM encoded certificates found in %s", *caFlag)
	}
	debugf("roots: %d from %s", len(pool.Subjects()), *caFlag)

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

func decodeAll(data []byte) (blocks []*pem.Block) {
	var block *pem.Block
	for {
		if block, data = pem.Decode(data); block == nil {
			return
		}
		if *allFlag || typesFlag.Contains(block.Type) {
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
