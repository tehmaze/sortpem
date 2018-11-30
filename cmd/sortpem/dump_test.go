package main

import (
	"bytes"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDumpCertificate(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(selfSignedRoot))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "Certificate:") {
		t.Fatalf("expected Certificate dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpCertificateRequest(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(intermediateRequest))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "Certificate Request:") {
		t.Fatalf("expected Certificate Request dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpDHParameters(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testDHParameters))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "Diffie-Hellman Parameters:") {
		t.Fatalf("expected Diffie-Hellman Parameters dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpPublicKey(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testECDSAPublicKey))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "ECDSA Public Key:") {
		t.Fatalf("expected ECDSA Public Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpPrivateKeyWithECDSA(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testPrivateKeyWithECDSA))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "ECDSA Private Key:") {
		t.Fatalf("expected ECDSA Private Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpPrivateKeyWithRSA(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testPrivateKeyWithRSA))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "RSA Private Key:") {
		t.Fatalf("expected RSA Private Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpECPrivateKey(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testECDSAPrivateKey))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "ECDSA Private Key:") {
		t.Fatalf("expected ECDSA Private Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpRSAPrivateKey(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testRSAPrivateKey))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "RSA Private Key:") {
		t.Fatalf("expected RSA Private Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpEncryptedRSAPrivateKey(t *testing.T) {
	*dumpFlag = true
	var (
		block, _ = pem.Decode([]byte(testRSAEncryptedPrivateKey))
		w        = new(bytes.Buffer)
	)
	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "Encrypted RSA Private Key:") {
		t.Fatalf("expected Encrypted RSA Private Key dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

func TestDumpUnknown(t *testing.T) {
	var (
		block = &pem.Block{Type: "UNKNOWN", Bytes: []byte("hello, gophers!")}
		w     = new(bytes.Buffer)
	)

	if err := dumpText(w, block); err != nil {
		t.Fatal(err)
	}

	dump := w.String()
	if !strings.HasPrefix(dump, "Unknown:") {
		t.Fatalf("expected Unknown dump, got %q", strings.SplitN(dump, "\n", 2)[0])
	}
}

const intermediateRequest = `-----BEGIN CERTIFICATE REQUEST-----
MIICYTCCAUkCAQAwHDEaMBgGA1UEAwwRVGVzdCBJbnRlcm1lZGlhdGUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnmZyDy85PlDT+62nK5vNoSGoLPaP9
cJYwlRhacherREzzZU3lQ8fEmq/dvCRlx0lOmbwN6/zWdZSzZR95aoD4zTVPJDyG
OhfcanAkQC41mSWPLoSy7jCEOG8VIEea7X6xkcic3hw0LFwJLGwYN0oQ3+jfEgic
tMnvPMq4DeN985KB2yCSAjeEC4aHDTtqhP1zI/OkntQxkfHwS1gVERBdTAG/xbRZ
MA49jh5v5/KOb/GuoYUjINFbZ1IllI4yp49GD8G2jVTdjOPy1LAsDttDaWDbe/nX
Ug49zp6bcXXH1Wh5amIGs3O6ewG4cxQPjhH9OQifY2QosUoTaKyVhrDlAgMBAAGg
ADANBgkqhkiG9w0BAQsFAAOCAQEAOhr9jFyms9wjYahpxJmxFAAPgsU2XUVcFGpg
5Gsp3TSh+8pvvKLuKwpnaqzy1SZfuCmX8NgD1kSzPOcqCVbBkNBlmEQR33hf6eJe
4L682CAMPG5mKd5ItRE3UwyZfGX1fI/kuk05ij+qkQM6xCOWoA4zy3ytTNCjtoM2
gNK1c7TZqCZRSlSNPmpEj+8YvXdCAKXc/Oryiym4mMPfMQVM2Q3r03nSGTDVdJ4M
J6tzFeT2QS4hTtlfMvQHbrlH6jXiOdgSOLNgwQC0QXeIpIOd3WqBDgQcPu+5KNWv
sxCX6ptUUiYj2GOvvnTL2ljl1lOzOW+AAN/Wxy1Ga5MBBrkZMA==
-----END CERTIFICATE REQUEST-----
`

const testDHParameters = `-----BEGIN DH PARAMETERS-----
MIGHAoGBAJ419DBEOgmQTzo5qXl5fQcN9TN455wkOL7052HzxxRVMyhYmwQcgJvh
1sa18fyfR9OiVEMYglOpkqVoGLN7qd5aQNNi5W7/C+VBdHTBJcGZJyyP5B3qcz32
9mLJKudlVudV0Qxk5qUJaPZ/xupz0NyoVpviuiBOI1gNi8ovSXWzAgEC
-----END DH PARAMETERS-----
`

const testPrivateKeyWithRSA = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMo6vOLBfsMu/E
Sn00199I7gv85C/viq626g7qnWYigZJKr1VcNitb0AsrA79dP9YncKeMgoZYpxC1
IQ/Au5sYTeSJ4Q07Wky0KkIQuY1DwtDL9kezphe7sAAWP147fPrFSYTSCDKXMhGO
wblx/XhngsL+mm+odS73AtD8OYd3/7A73AjYYTbbz4W8b1bPy8nt3sOdsYCp7d29
0vwCueRWhB67SpG9anlhb+4kghXKFRQfKLjdyPydG73aNXEi7p9GL8Pi+6Inux8f
Xm41daWrvzeBB2Ah08tYEERdbL+D0/mOFiQST4SmwwRpPvp0STe21dPpyOWI7Lu/
5wRXfsy7AgMBAAECggEATYjp7Ij6W20FOWs7u0zbdedztVLD8s+p2PYfxrbyXrqX
MiLyhaikjvnpcVfPJsasHm9pnCxMOMS76NTpAg5S+kdxAui5ObbB/zVPqMSVCIqE
z/K1QhT5QwyxS7yguItm/F8ZqvaeLHk0+9DcsZrnBtkdhpf/HGWh8McpZZdqg4U4
giwdigtv5oYGH4WwnrTKu9eaOanLOgb2JPRYlnJea+CdzbbvYuDHjgVWCCcVutU7
Mj48npFHADQoR2uNlLTCj9ADHZQYkhshoeN7E46rX3qTVsddpjze1tCCGjHbxiOy
Mom3C/U/vhkRgo0sjZVSWIv97fHkFWCtIryQEK65wQKBgQDy21Ui/2A3lTCFI6kK
wZMbdrEkpqQh2V+alr6JFoIvLDJrCeNVoEsp1nmI9joLtkKgWT1o6O7FcuGwbM92
1ou7oGpguNZ3FCTDAE1kjdwe4G5mpzK28E395GVC4AQczMypjls2JyGgaSwIwLJ7
OR3vUGQ8Av5RAu24Dr/u3jlK2wKBgQDXttqYS+faNoIBOvf3vSGlJju79qZjUmTg
n7AcAPtV4W3hsQD+F7KcdIebUn+HADakO+4Gc0qjB8KEUrVSNNsmKOeIp6c5OCYJ
1uhoVqkyr6pmDJP72bBkHvXAgCltXMCFzYXb/lTlbtSwyxbslqs8tdhywaBxtG74
70rUYtb7oQKBgQC4dLDgaRk6fl0g8qnlGovSMz9uuAc4EnNT5iUH2Im+rJIKzLLX
iW0tdNJQnbwOwzstsTo8YZdhbtVOfAbDm0b8lmXV2u5B+ZHGbodZ1YmYBhy0aU/S
tQh3y67BsYZOHZthOVe79NLMlLU2XK3ze7lp2CSZlCh3fYLy5nkPQ8g+OwKBgDOz
5Bj0uJGY1vgshhqe/l1zGIYozCCqMvuTysYrhhJDge7CWhaM34aYd5hG4cIdzvr2
UkrBf3Yr+fd1S3h0qsIus7ARXwdb6eIZ3IKFovA/InxrL10CBEE7GnQVQ9iujoaD
iD3+a6LCOcBWLRxv0IMworx+pFIciSypTioxto2BAoGBAOW54S4XDiTmxHPCVE5o
d0Dgb6uhnyhGjdhCDq+oF902CDvAeahsc1LQMy5BTmGL87e0ZjtvPue02r8MqvDi
IfZ6r+I4OPNGkiVIA33nXaK82zLMa+4yR1dPAvli+12bKWlxT4NoLkSAYQ70xB76
C8OruPn+sjA48wYifxVEJmHa
-----END PRIVATE KEY-----
`

const testPrivateKeyWithECDSA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjc8GHVPYYFRnTMUq
f08liq0kjAiThQ9EtGEJlAFdTcShRANCAAR2Fb/Q0w8ppdFYtRedcNfbTnkcLFxE
C17FBlJd8Sg9eOvfgWIMpMVCmL5gt/YOespTDFJbwsXEZ+jXJZKnTBnT
-----END PRIVATE KEY-----
`

const testECDSAPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII3PBh1T2GBUZ0zFKn9PJYqtJIwIk4UPRLRhCZQBXU3EoAoGCCqGSM49
AwEHoUQDQgAEdhW/0NMPKaXRWLUXnXDX2055HCxcRAtexQZSXfEoPXjr34FiDKTF
Qpi+YLf2DnrKUwxSW8LFxGfo1yWSp0wZ0w==
-----END EC PRIVATE KEY-----
`

const testECDSAPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdhW/0NMPKaXRWLUXnXDX2055HCxc
RAtexQZSXfEoPXjr34FiDKTFQpi+YLf2DnrKUwxSW8LFxGfo1yWSp0wZ0w==
-----END PUBLIC KEY-----
`

const testRSAPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzKOrziwX7DLvxEp9NNffSO4L/OQv74qutuoO6p1mIoGSSq9V
XDYrW9ALKwO/XT/WJ3CnjIKGWKcQtSEPwLubGE3kieENO1pMtCpCELmNQ8LQy/ZH
s6YXu7AAFj9eO3z6xUmE0ggylzIRjsG5cf14Z4LC/ppvqHUu9wLQ/DmHd/+wO9wI
2GE228+FvG9Wz8vJ7d7DnbGAqe3dvdL8ArnkVoQeu0qRvWp5YW/uJIIVyhUUHyi4
3cj8nRu92jVxIu6fRi/D4vuiJ7sfH15uNXWlq783gQdgIdPLWBBEXWy/g9P5jhYk
Ek+EpsMEaT76dEk3ttXT6cjliOy7v+cEV37MuwIDAQABAoIBAE2I6eyI+lttBTlr
O7tM23Xnc7VSw/LPqdj2H8a28l66lzIi8oWopI756XFXzybGrB5vaZwsTDjEu+jU
6QIOUvpHcQLouTm2wf81T6jElQiKhM/ytUIU+UMMsUu8oLiLZvxfGar2nix5NPvQ
3LGa5wbZHYaX/xxlofDHKWWXaoOFOIIsHYoLb+aGBh+FsJ60yrvXmjmpyzoG9iT0
WJZyXmvgnc2272Lgx44FVggnFbrVOzI+PJ6RRwA0KEdrjZS0wo/QAx2UGJIbIaHj
exOOq196k1bHXaY83tbQghox28YjsjKJtwv1P74ZEYKNLI2VUliL/e3x5BVgrSK8
kBCuucECgYEA8ttVIv9gN5UwhSOpCsGTG3axJKakIdlfmpa+iRaCLywyawnjVaBL
KdZ5iPY6C7ZCoFk9aOjuxXLhsGzPdtaLu6BqYLjWdxQkwwBNZI3cHuBuZqcytvBN
/eRlQuAEHMzMqY5bNichoGksCMCyezkd71BkPAL+UQLtuA6/7t45StsCgYEA17ba
mEvn2jaCATr3970hpSY7u/amY1Jk4J+wHAD7VeFt4bEA/heynHSHm1J/hwA2pDvu
BnNKowfChFK1UjTbJijniKenOTgmCdboaFapMq+qZgyT+9mwZB71wIApbVzAhc2F
2/5U5W7UsMsW7JarPLXYcsGgcbRu+O9K1GLW+6ECgYEAuHSw4GkZOn5dIPKp5RqL
0jM/brgHOBJzU+YlB9iJvqySCsyy14ltLXTSUJ28DsM7LbE6PGGXYW7VTnwGw5tG
/JZl1druQfmRxm6HWdWJmAYctGlP0rUId8uuwbGGTh2bYTlXu/TSzJS1Nlyt83u5
adgkmZQod32C8uZ5D0PIPjsCgYAzs+QY9LiRmNb4LIYanv5dcxiGKMwgqjL7k8rG
K4YSQ4HuwloWjN+GmHeYRuHCHc769lJKwX92K/n3dUt4dKrCLrOwEV8HW+niGdyC
haLwPyJ8ay9dAgRBOxp0FUPYro6Gg4g9/muiwjnAVi0cb9CDMKK8fqRSHIksqU4q
MbaNgQKBgQDlueEuFw4k5sRzwlROaHdA4G+roZ8oRo3YQg6vqBfdNgg7wHmobHNS
0DMuQU5hi/O3tGY7bz7ntNq/DKrw4iH2eq/iODjzRpIlSAN9512ivNsyzGvuMkdX
TwL5YvtdmylpcU+DaC5EgGEO9MQe+gvDq7j5/rIwOPMGIn8VRCZh2g==
-----END RSA PRIVATE KEY-----
`

const testRSAPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzKOrziwX7DLvxEp9NNff
SO4L/OQv74qutuoO6p1mIoGSSq9VXDYrW9ALKwO/XT/WJ3CnjIKGWKcQtSEPwLub
GE3kieENO1pMtCpCELmNQ8LQy/ZHs6YXu7AAFj9eO3z6xUmE0ggylzIRjsG5cf14
Z4LC/ppvqHUu9wLQ/DmHd/+wO9wI2GE228+FvG9Wz8vJ7d7DnbGAqe3dvdL8Arnk
VoQeu0qRvWp5YW/uJIIVyhUUHyi43cj8nRu92jVxIu6fRi/D4vuiJ7sfH15uNXWl
q783gQdgIdPLWBBEXWy/g9P5jhYkEk+EpsMEaT76dEk3ttXT6cjliOy7v+cEV37M
uwIDAQAB
-----END PUBLIC KEY-----
`

const testRSAEncryptedPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: id-aes128-GCM,E2BA1DF7D13ECB3CF0601084

+13JeVx82hzAKIvkeU3MKWANQRai4ca5szTfTJr+52+begnXg+tkRxZtd90u+Ycd
2aRpY0lJOFWpBZBDbBisKaxd8B5DO1+zAQJAtfTl0jMTkUA9KG3npD3qNp51si3k
crF7mdgpsc2qKhpHxw7JVQwpwprUPNJkT4ThttF7Jt9LuubQkx7jIyaP6SWf3v61
ULJopoOAAQp+DCwmMviSnwPX1b4zy6x8+DgsawhSB3fckVxx1b1YErcQQ6e50hu1
lrD/vP4STyBot11DPHKjcpItYP6XRi81v5RRo8sf9b2ISc4V2mX+79pBNOH6Qkr+
4JjmZVmPXWVZgKfXF1OsMtYPwJltzHh4uB2xSnZSsfh69jLJ+M7wMM9+KbL0U9er
uK9nSeP34eXn/+odyY0SceYxxl1wrldooIZJI5Zchv7pYcHYUXHnrvxSufBdZ+cW
fuynNUo9WZF+FdjcNkpIYtYP2MWxcr6RDvh5hu+G7wR8ru+Q1pN8jIQSlXBsR3zI
G/FAZltQ8M1Km/hTc8T4DWwGOeNWhJm3kk7tNYInAYq7M9Y84q42JhyeG6gymn7P
JwTkcZvyT52k38s1mTEsdSVLSoDD7qCv3hFnT9g8jcdbR2AWOKS/QOw2W9r8EPxA
LmGIkx/C7IbKili8BZEjPkO8iQOWTla23u/Iv6hwJRox4VZfev40OgCX3ZZLwHna
ktip1Em2OXFwQp4CoEgS2wj1sdgU8Ji3kGzaul7Bu148QMeUrh/42L5U+XU40GXL
SYI7NmSGuw7UW7q2Tfg5pIq1B7FKyVQAl0rrYcqJ4iJQ6P/LKYbCZPYB3qTWDzhU
X4g96nqjCSSy9zIIvGgXWO2vQQIiNXWHtQxFGWaYm/MjiLAfgSOLXSBloMvlNfCY
28w8CkxSrW8lXKUrfht41vEwPg9hLLUSR9oRhUn0SSpVJjfUW7DuDM9xVB6/yCvg
UxswSFcVS4BUcetj/8DITzUi1elSlniC+jKkfucd/zE4BBPAQoWRLxA+J/NlyHlV
JHg1/BjmJ8oTMHCPs+zOYXmd23ObVl8GwC/lDT6mEP8kF4uyHO2+deAAeScQ5Zf1
UYxq5WlV0cT0km/PF9hwGVjFy/T+eI4cqUXO+R0REdZGV5w2v9kjlB6SdAJyqieB
I1yivKojVkWFCo6Z0bGuKmSu1doKauP4lon7rvOlN6n33ImoqWhxEPqJvuOxhlHh
Bb9A0PIKfg/PF14tgf9ZR5Wvx9GpSwpoAhqQDsO2MsnPNpcP8etMYJB9AFw5CMwP
gfWYNYiDas8YhiAc9CAHpePym2L6TFMZwDp5yItvwfEvpWkPdE5PKcbm65bcZemk
IQE1cZRcToh/9Wjpz6rY13RN9WWpXsqAaz0YwD2PDvLvTmHjU7ejPQiYLC9hMC1W
3XTMSInfouKymz4nYCHVAsneAT2oWCwoq6fFMqdcyTWfiJcfDBm81jAJiegAMQ71
5vh6AjVY3KAmSF8HOdWlB31GB4FRZ2b/WM0fZ3c0x5QJNLW2QN7VwqRF3lk5ltFx
akNfuTh+8L1O4xbwu4dHBtIlQ9DOLPS9MUJ+ugXA4j+8zNLPlF33iw==
-----END RSA PRIVATE KEY-----
`
