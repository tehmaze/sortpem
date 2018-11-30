package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

const timeFormat = "Jan _2 15:04:05 2006 MST"

type indentWriter struct {
	io.Writer
	indent int
}

// Indent is the total indetation size.
func (w indentWriter) Indent() int {
	var (
		indent = w.indent
		node   = w
	)
	for {
		if next, ok := node.Writer.(indentWriter); ok {
			indent += next.indent
			node = next
		} else {
			break
		}
	}
	return indent
}

// Root writer.
func (w indentWriter) Root() io.Writer {
	var node = w
	for {
		if next, ok := node.Writer.(indentWriter); ok {
			node = next
		} else {
			break
		}
	}
	return node.Writer
}

func (w indentWriter) Write(p []byte) (int, error) {
	return w.Writer.Write(append(bytes.Repeat([]byte{0x20}, w.indent), p...))
}

const (
	procType  = "Proc-Type"
	dekInfo   = "DEK-Info"
	encrypted = "ENCRYPTED"
)

// dumpText decodes and dumps the contents of a PEM block; only errors
// encountered during writing shall be reported
func dumpText(w io.Writer, block *pem.Block) (err error) {
	debugf("dump: %s block", block.Type)
	switch block.Type {
	case certificate:
		return dumpCertificateData(w, block.Bytes)
	case certificateRequest:
		return dumpCertificateRequestData(w, block.Bytes)
	case certificateRevocationList:
		return dumpCertificateRevocationListData(w, block.Bytes)
	case dhParameters:
		return dumpDHParametersData(w, block.Bytes)
	case publicKey:
		return dumpPublicKeyData(w, block.Bytes)
	case privateKey:
		if strings.HasSuffix(block.Headers[procType], encrypted) {
			return dumpEncryptedPrivateKeyData(w, block.Bytes, block.Headers)
		}
		return dumpPrivateKeyData(w, block.Bytes)
	case ecPrivateKey:
		if strings.HasSuffix(block.Headers[procType], encrypted) {
			return dumpEncryptedECDSAPrivateKeyData(w, block.Bytes, block.Headers)
		}
		return dumpECDSAPrivateKeyData(w, block.Bytes)
	case rsaPrivateKey:
		if strings.HasSuffix(block.Headers[procType], encrypted) {
			return dumpEncryptedRSAPrivateKeyData(w, block.Bytes, block.Headers)
		}
		return dumpRSAPrivateKeyData(w, block.Bytes)
	case opensshPrivateKey:
		return dumpOpenSSHPrivateKeyData(w, block.Bytes)
	default:
		fmt.Fprintf(w, "%s:\n", strings.Title(strings.ToLower(block.Type)))
		return dumpBytes(indentWriter{w, 2}, block.Bytes)
	}
}

func dumpBytes(w io.Writer, data []byte) (err error) {
	if len(data) == 0 {
		_, err = fmt.Fprintln(w, "(empty)")
		return
	}
	var (
		//rightChars [18]byte
		buf  [14]byte
		line = new(bytes.Buffer)
		used int  // number of bytes in the current line
		l    int  // number of chars in the current byte
		n    uint // number of bytes, total
	)
	for i := range data {
		if used == 0 {
			// At the beginning of a line we print the current
			// offset in hex.
			buf[1] = byte(n >> 16)
			buf[2] = byte(n >> 8)
			buf[3] = byte(n)
			hex.Encode(buf[4:], buf[:4])
			buf[12] = ' '
			buf[13] = ' '
			if len(data) <= 0xfff {
				buf[6] = '0'
				buf[7] = 'x'
				line.Write(buf[6:])
			} else {
				buf[4] = '0'
				buf[5] = 'x'
				line.Write(buf[4:])
			}
		}
		hex.Encode(buf[:], data[i:i+1])
		buf[2] = ' '
		l = 3
		if used == 7 {
			// There's an additional space after the 8th byte.
			buf[3] = ' '
			l = 4
		} else if used == 15 {
			l = 3
		}
		line.Write(buf[:l])
		n++
		used++
		n++
		if used == 16 {
			line.WriteByte('\n')
			if _, err = w.Write(line.Bytes()); err != nil {
				return
			}
			line.Reset()
			used = 0
		}
	}
	return
}

func paddedBytes(b []byte) (out []byte) {
	lb := len(b)
	out = make([]byte, 0, 3*lb)
	ox := out[lb : 3*lb]
	hex.Encode(ox, b)
	for i := 0; i < len(ox); i += 2 {
		out = append(out, ox[i], ox[i+1], ':')
	}
	out = out[:len(out)-1]
	return
}

func dumpPaddedBytes(w io.Writer, b []byte) (err error) {
	var (
		buf = paddedBytes(b)
		dst = new(bytes.Buffer)
		out [3]byte
		n   int
	)

	// Write out colon separated hex without the last colon
	for i := 0; i < len(buf); i, buf = i+n, buf[n:] {
		n = copy(out[:], buf)
		if _, err = dst.Write(out[:n]); err != nil {
			return
		}
	}

	// Write out remainder with a trailing newline
	if len(buf) > 0 {
		if _, err = dst.Write(append(buf, '\n')); err != nil {
			return
		}
		buf = buf[:0]
	} else {
		if _, err = dst.Write([]byte{'\n'}); err != nil {
			return
		}
	}

	// Flush our buffer
	_, err = w.Write(dst.Bytes())
	return
}

func dumpPaddedBytesLimit(writer io.Writer, b []byte, limit int) (err error) {
	var (
		w   io.Writer
		pad []byte
		buf = paddedBytes(b)
		out [3]byte
		n   int
	)

	// Find correct limit and root writer
	limit -= 3 // we emit two hextets and a colon for each byte in b
	if i, ok := writer.(indentWriter); ok {
		indent := i.Indent()
		pad = bytes.Repeat([]byte{0x20}, indent)
		limit -= indent
		w = i.Root()
	} else {
		w = writer
	}

	// Write out colon separated hex without the last colon
	for len(buf) > 0 {
		if len(pad) > 0 {
			if _, err = w.Write(pad); err != nil {
				return
			}
		}
		for i := 0; i < limit && len(buf) > 2; i, buf = i+n, buf[n:] {
			n = copy(out[:], buf)
			if _, err = w.Write(out[:n]); err != nil {
				return
			}
		}

		// Write out remainder with a trailing newline
		if len(buf) == 2 {
			if _, err = w.Write(append(buf, '\n')); err != nil {
				return
			}
			buf = buf[:0]
		} else {
			if _, err = w.Write([]byte{'\n'}); err != nil {
				return
			}
		}
	}

	return
}

func dumpStringsLimit(writer io.Writer, title string, values []string, limit int) (err error) {
	if len(values) == 0 {
		// Fast way out
		return
	}

	var (
		w   io.Writer
		pad []byte
		buf = new(bytes.Buffer)
	)

	// Find correct limit and root writer
	limit -= len(title) + 2 // we emit the title, plus a colon and a space
	if i, ok := writer.(indentWriter); ok {
		indent := i.Indent()
		pad = bytes.Repeat([]byte{0x20}, indent)
		limit -= indent
		w = i.Root()
	} else {
		w = writer
	}

	for len(values) > 0 {
		fmt.Fprintf(buf, "%s: %s", title, values[0])
		values = values[1:]
		for len(values) > 0 && buf.Len()+len(values[0])+2 < limit {
			fmt.Fprintf(buf, ", %s", values[0])
			values = values[1:]
		}
		buf.WriteByte('\n')
		if _, err = w.Write(pad); err != nil {
			return
		}
		if _, err = w.Write(buf.Bytes()); err != nil {
			return
		}
		buf.Reset()
	}

	return
}

func dumpEncryptedData(w io.Writer, kind string, data []byte, headers map[string]string) (err error) {
	fmt.Fprintf(w, "Encrypted %s:\n", strings.Title(kind))
	if info, ok := headers[dekInfo]; ok {
		cipher := strings.ToUpper(strings.TrimPrefix(strings.SplitN(info, ",", 2)[0], "id-"))
		fmt.Fprintf(w, "  Cipher: %s\n", cipher)
	} else {
		fmt.Fprintln(w, "  Cipher: Unknown")
	}
	return
}

func dumpOID(w io.Writer, oid asn1.ObjectIdentifier, extra ...string) (err error) {
	if s := oidName(oid); s != "" {
		_, err = fmt.Fprintf(w, "%s (%s) %s\n", s, oid, strings.Join(extra, " "))
		return
	}
	_, err = fmt.Fprintf(w, "%s %s\n", oid, strings.Join(extra, " "))
	return
}
