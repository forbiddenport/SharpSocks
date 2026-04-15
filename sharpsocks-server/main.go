package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	FrameAuthChallenge   byte = 0x01
	FrameAuthResponse    byte = 0x02
	FrameAuthSuccess     byte = 0x03
	FrameAuthFailure     byte = 0x04
	FrameChannelOpen     byte = 0x10
	FrameChannelOpenOk   byte = 0x11
	FrameChannelOpenFail byte = 0x12
	FrameChannelData     byte = 0x20
	FrameChannelClose    byte = 0x21
	FrameKeepalive       byte = 0x30
	FrameKeepaliveAck    byte = 0x31
)

const (
	headerSize     = 9
	maxPayloadSize = 1 * 1024 * 1024
	nonceSize      = 32
	keySize        = 32
	macSize        = 32
	sessionKeySize = 64
	ivSize         = 16
	pbkdf2Iter     = 10000
	bufferSize     = 65536
	authTimeout    = 10 * time.Second
)

var verbose bool

func logv(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}

// --- protocol ---

type Frame struct {
	Type      byte
	ChannelID int32
	Payload   []byte
}

func readExact(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

func readFrame(r io.Reader, sessionKey []byte) (*Frame, error) {
	hdr := make([]byte, headerSize)
	if err := readExact(r, hdr); err != nil {
		return nil, err
	}

	f := &Frame{
		Type:      hdr[0],
		ChannelID: int32(binary.BigEndian.Uint32(hdr[1:5])),
	}
	length := int(binary.BigEndian.Uint32(hdr[5:9]))

	if length < 0 || length > maxPayloadSize {
		return nil, fmt.Errorf("payload size out of range: %d", length)
	}

	if sessionKey != nil && length == 0 {
		return nil, errors.New("received unprotected frame on encrypted channel")
	}

	f.Payload = make([]byte, length)
	if length > 0 {
		if err := readExact(r, f.Payload); err != nil {
			return nil, err
		}
		if sessionKey != nil {
			if length < ivSize+aes.BlockSize+macSize {
				return nil, errors.New("encrypted payload too short")
			}

			encKey := sessionKey[:keySize]
			macKey := sessionKey[keySize:]
			encLen := length - macSize
			receivedMac := f.Payload[encLen:]

			h := hmac.New(sha256.New, macKey)
			h.Write(hdr)
			h.Write(f.Payload[:encLen])
			expectedMac := h.Sum(nil)

			if subtle.ConstantTimeCompare(receivedMac, expectedMac) != 1 {
				return nil, errors.New("frame authentication failed")
			}

			var err error
			f.Payload, err = aesCBCDecrypt(f.Payload[:encLen], encKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt: %w", err)
			}
		}
	}

	return f, nil
}

func writeFrame(w io.Writer, f *Frame, sessionKey []byte, mu *sync.Mutex) error {
	payload := f.Payload

	if sessionKey != nil {
		encKey := sessionKey[:keySize]
		macKey := sessionKey[keySize:]

		encrypted, err := aesCBCEncrypt(payload, encKey)
		if err != nil {
			return err
		}

		hdr := make([]byte, headerSize)
		hdr[0] = f.Type
		binary.BigEndian.PutUint32(hdr[1:5], uint32(f.ChannelID))
		binary.BigEndian.PutUint32(hdr[5:9], uint32(len(encrypted)+macSize))

		h := hmac.New(sha256.New, macKey)
		h.Write(hdr)
		h.Write(encrypted)
		mac := h.Sum(nil)

		packet := make([]byte, headerSize+len(encrypted)+macSize)
		copy(packet, hdr)
		copy(packet[headerSize:], encrypted)
		copy(packet[headerSize+len(encrypted):], mac)

		if mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}
		_, err = w.Write(packet)
		return err
	}

	packet := make([]byte, headerSize+len(payload))
	packet[0] = f.Type
	binary.BigEndian.PutUint32(packet[1:5], uint32(f.ChannelID))
	binary.BigEndian.PutUint32(packet[5:9], uint32(len(payload)))
	copy(packet[headerSize:], payload)

	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	_, err := w.Write(packet)
	return err
}

// --- crypto ---

func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	_, err := rand.Read(nonce)
	return nonce, err
}

func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func deriveKey(password string, serverNonce, clientNonce []byte) []byte {
	salt := make([]byte, len(serverNonce)+len(clientNonce))
	copy(salt, serverNonce)
	copy(salt[len(serverNonce):], clientNonce)
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iter, sessionKeySize, sha256.New)
}

func aesCBCEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	result := make([]byte, ivSize+len(encrypted))
	copy(result, iv)
	copy(result[ivSize:], encrypted)
	return result, nil
}

func aesCBCDecrypt(data, key []byte) ([]byte, error) {
	if len(data) < ivSize+aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := data[:ivSize]
	ciphertext := data[ivSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext not aligned to block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	padLen := int(plaintext[len(plaintext)-1])
	if padLen < 1 || padLen > aes.BlockSize {
		return nil, errors.New("invalid PKCS7 padding")
	}
	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		if plaintext[i] != byte(padLen) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return plaintext[:len(plaintext)-padLen], nil
}

func generateSelfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"SharpSocks"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	fp := sha256.Sum256(certDER)
	return tlsCert, hex.EncodeToString(fp[:]), nil
}

// --- server ---

type SocksChannel struct {
	ID     int32
	Conn   net.Conn
	Ready  chan bool
	Active bool
	mu     sync.Mutex
}

type Server struct {
	password  string
	socksUser string
	socksPass string
	agentBind string
	agentPort int
	socksBind string
	socksPort int
	transport string

	agentConn  net.Conn
	sessionKey []byte
	writeMu    sync.Mutex
	channels   sync.Map
	nextChanID int32
	chanMu     sync.Mutex
	agentReady chan struct{}
}

func (s *Server) nextChannel() int32 {
	s.chanMu.Lock()
	defer s.chanMu.Unlock()
	s.nextChanID++
	return s.nextChanID
}

func (s *Server) sendToAgent(f *Frame) error {
	conn := s.agentConn
	if conn == nil {
		return errors.New("no agent connected")
	}
	return writeFrame(conn, f, s.sessionKey, &s.writeMu)
}

func (s *Server) doAuth(conn net.Conn) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(authTimeout))
	defer conn.SetDeadline(time.Time{})

	serverNonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	if err := writeFrame(conn, &Frame{Type: FrameAuthChallenge, Payload: serverNonce}, nil, nil); err != nil {
		return nil, err
	}

	resp, err := readFrame(conn, nil)
	if err != nil {
		return nil, err
	}
	if resp.Type != FrameAuthResponse || len(resp.Payload) < nonceSize+32 {
		return nil, errors.New("invalid auth response")
	}

	clientNonce := resp.Payload[:nonceSize]
	clientHMAC := resp.Payload[nonceSize : nonceSize+32]

	combined := make([]byte, nonceSize*2)
	copy(combined, serverNonce)
	copy(combined[nonceSize:], clientNonce)

	expected := computeHMAC([]byte(s.password), combined)

	if subtle.ConstantTimeCompare(clientHMAC, expected) != 1 {
		writeFrame(conn, &Frame{Type: FrameAuthFailure}, nil, nil)
		return nil, errors.New("authentication failed")
	}

	sessionKey := deriveKey(s.password, serverNonce, clientNonce)
	writeFrame(conn, &Frame{Type: FrameAuthSuccess}, nil, nil)
	return sessionKey, nil
}

func (s *Server) agentReaderLoop() {
	defer func() {
		s.agentConn = nil
		s.sessionKey = nil
		s.cleanupChannels()
	}()

	for {
		frame, err := readFrame(s.agentConn, s.sessionKey)
		if err != nil {
			log.Printf("agent connection lost: %v", err)
			return
		}

		switch frame.Type {
		case FrameChannelOpenOk, FrameChannelOpenFail:
			if val, ok := s.channels.Load(frame.ChannelID); ok {
				ch := val.(*SocksChannel)
				ch.Ready <- (frame.Type == FrameChannelOpenOk)
			}

		case FrameChannelData:
			if val, ok := s.channels.Load(frame.ChannelID); ok {
				ch := val.(*SocksChannel)
				ch.mu.Lock()
				active := ch.Active
				ch.mu.Unlock()
				if active {
					if _, err := ch.Conn.Write(frame.Payload); err != nil {
						s.closeChannel(ch)
					}
				}
			}

		case FrameChannelClose:
			if val, ok := s.channels.Load(frame.ChannelID); ok {
				ch := val.(*SocksChannel)
				ch.mu.Lock()
				ch.Active = false
				ch.mu.Unlock()
				ch.Conn.Close()
				s.channels.Delete(frame.ChannelID)
			}

		case FrameKeepalive:
			s.sendToAgent(&Frame{Type: FrameKeepaliveAck})

		case FrameKeepaliveAck:
		}
	}
}

func (s *Server) closeChannel(ch *SocksChannel) {
	ch.mu.Lock()
	ch.Active = false
	ch.mu.Unlock()
	ch.Conn.Close()
	s.channels.Delete(ch.ID)
}

func (s *Server) cleanupChannels() {
	s.channels.Range(func(key, val any) bool {
		ch := val.(*SocksChannel)
		ch.mu.Lock()
		ch.Active = false
		ch.mu.Unlock()
		ch.Conn.Close()
		s.channels.Delete(key)
		return true
	})
}

func (s *Server) handleSocksClient(conn net.Conn) {
	var channel *SocksChannel

	defer func() {
		if channel != nil {
			s.closeChannel(channel)
			s.sendToAgent(&Frame{Type: FrameChannelClose, ChannelID: channel.ID})
		} else {
			conn.Close()
		}
	}()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 257)
	if err := readExact(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	nmethods := int(buf[1])
	if nmethods == 0 {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	if err := readExact(conn, buf[:nmethods]); err != nil {
		return
	}

	hasUserPass := false
	for i := 0; i < nmethods; i++ {
		if buf[i] == 0x02 {
			hasUserPass = true
			break
		}
	}

	if !hasUserPass {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	conn.Write([]byte{0x05, 0x02})

	if err := readExact(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x01 {
		return
	}

	ulen := int(buf[1])
	user := make([]byte, ulen)
	if err := readExact(conn, user); err != nil {
		return
	}

	if err := readExact(conn, buf[:1]); err != nil {
		return
	}
	plen := int(buf[0])
	pass := make([]byte, plen)
	if err := readExact(conn, pass); err != nil {
		return
	}

	userOk := subtle.ConstantTimeCompare(user, []byte(s.socksUser))
	passOk := subtle.ConstantTimeCompare(pass, []byte(s.socksPass))
	if userOk&passOk != 1 {
		conn.Write([]byte{0x01, 0x01})
		return
	}
	conn.Write([]byte{0x01, 0x00})

	if err := readExact(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		sendSocksReply(conn, 0x07)
		return
	}

	var targetHost string
	atyp := buf[3]

	switch atyp {
	case 0x01:
		if err := readExact(conn, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()

	case 0x03:
		if err := readExact(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if domainLen == 0 {
			sendSocksReply(conn, 0x01)
			return
		}
		if err := readExact(conn, buf[:domainLen]); err != nil {
			return
		}
		targetHost = string(buf[:domainLen])

	case 0x04:
		ipv6 := make([]byte, 16)
		if err := readExact(conn, ipv6); err != nil {
			return
		}
		targetHost = net.IP(ipv6).String()

	default:
		sendSocksReply(conn, 0x08)
		return
	}

	if err := readExact(conn, buf[:2]); err != nil {
		return
	}
	targetPort := int(buf[0])<<8 | int(buf[1])

	if targetPort < 1 || targetPort > 65535 {
		sendSocksReply(conn, 0x01)
		return
	}

	logv("socks connect %s:%d", targetHost, targetPort)

	if s.agentConn == nil {
		sendSocksReply(conn, 0x01)
		return
	}

	channelID := s.nextChannel()
	channel = &SocksChannel{
		ID:     channelID,
		Conn:   conn,
		Ready:  make(chan bool, 1),
		Active: true,
	}
	s.channels.Store(channelID, channel)

	target := targetHost + ":" + strconv.Itoa(targetPort)
	s.sendToAgent(&Frame{
		Type:      FrameChannelOpen,
		ChannelID: channelID,
		Payload:   []byte(target),
	})

	select {
	case ok := <-channel.Ready:
		if !ok {
			logv("channel %d connect refused", channelID)
			sendSocksReply(conn, 0x05)
			return
		}
	case <-time.After(30 * time.Second):
		logv("channel %d connect timeout", channelID)
		sendSocksReply(conn, 0x01)
		return
	}

	sendSocksReply(conn, 0x00)
	conn.SetDeadline(time.Time{})

	logv("channel %d established -> %s:%d", channelID, targetHost, targetPort)

	relayBuf := make([]byte, bufferSize)
	for {
		channel.mu.Lock()
		active := channel.Active
		channel.mu.Unlock()
		if !active {
			break
		}

		n, err := conn.Read(relayBuf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, relayBuf[:n])
			s.sendToAgent(&Frame{
				Type:      FrameChannelData,
				ChannelID: channelID,
				Payload:   data,
			})
		}
		if err != nil {
			break
		}
	}
}

func sendSocksReply(conn net.Conn, rep byte) {
	conn.Write([]byte{
		0x05, rep, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
}

func main() {
	s := &Server{
		agentReady: make(chan struct{}),
	}

	flag.StringVar(&s.password, "agent-password", "", "Pre-shared password for agent authentication (required)")
	flag.StringVar(&s.socksUser, "socks-username", "", "SOCKS5 proxy username (required)")
	flag.StringVar(&s.socksPass, "socks-password", "", "SOCKS5 proxy password (required)")
	flag.StringVar(&s.agentBind, "agent-bind", "0.0.0.0", "Agent listener bind address")
	flag.IntVar(&s.agentPort, "agent-port", 443, "Agent listener port")
	flag.StringVar(&s.socksBind, "socks-bind", "127.0.0.1", "SOCKS5 proxy bind address")
	flag.IntVar(&s.socksPort, "socks-port", 1080, "SOCKS5 listener port")
	flag.StringVar(&s.transport, "transport", "raw", "Agent transport: raw or tls")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	if s.password == "" || s.socksUser == "" || s.socksPass == "" {
		log.Fatal("-agent-password, -socks-username, and -socks-password are required")
	}
	if s.transport != "raw" && s.transport != "tls" {
		log.Fatal("-transport must be raw or tls")
	}

	log.Printf("SharpSocks server")
	log.Printf("socks proxy: %s:%d", s.socksBind, s.socksPort)

	socksAddr := fmt.Sprintf("%s:%d", s.socksBind, s.socksPort)
	socksListener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", socksAddr, err)
	}

	go func() {
		for {
			conn, err := socksListener.Accept()
			if err != nil {
				logv("socks accept error: %v", err)
				continue
			}
			if s.agentConn == nil {
				conn.Close()
				continue
			}
			go s.handleSocksClient(conn)
		}
	}()

	agentAddr := fmt.Sprintf("%s:%d", s.agentBind, s.agentPort)
	var agentListener net.Listener
	agentListener, err = net.Listen("tcp", agentAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", agentAddr, err)
	}

	if s.transport == "tls" {
		cert, fingerprint, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("failed to generate tls certificate: %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		agentListener = tls.NewListener(agentListener, tlsConfig)
		log.Printf("tls certificate generated")
		log.Printf("tls fingerprint: %s", fingerprint)
		log.Printf("agent listener: %s:%d (tls)", s.agentBind, s.agentPort)
	} else {
		log.Printf("agent listener: %s:%d (raw)", s.agentBind, s.agentPort)
	}

	for {
		log.Printf("waiting for agent connection...")
		conn, err := agentListener.Accept()
		if err != nil {
			log.Printf("agent accept error: %v", err)
			continue
		}

		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		log.Printf("agent connected from %s", conn.RemoteAddr())

		sessionKey, err := s.doAuth(conn)
		if err != nil {
			log.Printf("agent authentication failed: %v", err)
			conn.Close()
			continue
		}

		if s.agentConn != nil {
			s.agentConn.Close()
			s.cleanupChannels()
		}

		s.agentConn = conn
		s.sessionKey = sessionKey
		s.nextChanID = 0

		log.Printf("agent authenticated")

		s.agentReaderLoop()

		log.Printf("agent disconnected")
	}
}
