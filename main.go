/*
Based on https://sourceforge.net/p/nbd/code/ci/master/tree/doc/proto.md
*/

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"math/rand"
	"net"
	"os"
)

var (
	host   = flag.String("host", "localhost", "Hostname")
	port   = flag.Uint("port", 10809, "Port")
	data   = flag.String("data", "", "Data to write")
	offset = flag.Uint64("offset", 0, "Offset")
)

const (
	NBD_SERVER_MAGIC       = 0x4e42444d41474943
	NBD_CLIENTSERV_MAGIC   = 0x00420281861253
	NBD_HANDSHAKE_MSG_SIZE = 0x98
)

const (
	NBD_CMD_READ  = 0
	NBD_CMD_WRITE = 1
)

func main() {
	flag.Parse()

	if *data == "" {
		fmt.Fprintf(os.Stderr, "Data to write ccentrinannot be empty")
		os.Exit(1)
	}

	nbd := NewNBD(*host, uint16(*port))
	if err := nbd.Connect(); err != nil {
		panic(err)
	}

	if err := nbd.Handshake(); err != nil {
		panic(err)
	}

	/*
		data, err := nbd.Read(0, 1024)
		if err != nil {
			panic(err)
		}

		fmt.Println(string(data))
	*/

	if err := nbd.Write(*offset, []byte(*data)); err != nil {
		panic(err)
	}
}

type NBD struct {
	host       string
	port       uint16
	conn       net.Conn
	exportSize uint64
	flags      uint32
}

func NewNBD(host string, port uint16) *NBD {
	return &NBD{
		host,
		port,
		nil,
		0,
		0,
	}
}

func (n *NBD) Connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", n.host, n.port))
	if err != nil {
		return err
	}

	n.conn = conn
	return nil
}

func (n *NBD) Handshake() error {
	data := make([]byte, NBD_HANDSHAKE_MSG_SIZE)
	num, err := io.ReadFull(n.conn, data)
	if err != nil {
		return err
	}

	if num < NBD_HANDSHAKE_MSG_SIZE {
		return errors.New("handshake message is too short")
	}

	magic := binary.BigEndian.Uint64(data[0:8])
	if magic != NBD_SERVER_MAGIC {
		return fmt.Errorf("bad magic value: %d", magic)
	}

	clientServMagic := binary.BigEndian.Uint64(data[8:16])
	if clientServMagic != NBD_CLIENTSERV_MAGIC {
		return fmt.Errorf("bad cliserv_magic value: %d", clientServMagic)
	}

	exportSize := binary.BigEndian.Uint64(data[16:24])
	n.exportSize = exportSize

	flags := binary.BigEndian.Uint32(data[24:28])
	n.flags = flags

	reserved := data[28:]
	for i := range reserved {
		if reserved[i] != 0 {
			return fmt.Errorf("invalid data in reserved bytes %d", reserved[i])
		}
	}

	return nil
}

const (
	NBD_REQUEST_MAGIC = 0x25609513
	NBD_REPLY_MAGIC   = 0x67446698
)

type NBDRequest struct {
	Magic   uint32
	Type    uint16
	Command uint16
	Handle  uint64
	Offset  uint64
	Length  uint32
	Data    []byte
}

func (r *NBDRequest) Pack() []byte {
	result := make([]byte, 28, 28)
	binary.BigEndian.PutUint32(result[0:4], r.Magic)
	binary.BigEndian.PutUint16(result[4:6], r.Type)
	binary.BigEndian.PutUint16(result[6:8], r.Command)
	binary.BigEndian.PutUint64(result[8:16], r.Handle)
	binary.BigEndian.PutUint64(result[16:24], r.Offset)
	binary.BigEndian.PutUint32(result[24:28], r.Length)
	return append(result, r.Data...)
}

const (
	NBD_REPLY_SIZE = 16
)

type NBDReply struct {
	Magic  uint32
	Error  uint32
	Handle uint64
	Data   []byte
}

func UnpackReplyFromData(data []byte) (*NBDReply, error) {
	if len(data) < 16 {
		return nil, errors.New("data is too short")
	}

	return &NBDReply{
		binary.BigEndian.Uint32(data[0:4]),
		binary.BigEndian.Uint32(data[4:8]),
		binary.BigEndian.Uint64(data[8:16]),
		data[16:],
	}, nil
}

func (n *NBD) sendRequest(request *NBDRequest) (*NBDReply, error) {
	data := request.Pack()

	num, err := n.conn.Write(data)
	if err != nil {
		return nil, err
	}

	if num != len(data) {
		return nil, errors.New("couldn't send all data")
	}

	rspLen := uint32(0)
	switch request.Command {
	case NBD_CMD_READ:
		rspLen = NBD_REPLY_SIZE + request.Length
	case NBD_CMD_WRITE:
		rspLen = NBD_REPLY_SIZE
	}

	buf := make([]byte, rspLen)
	readNum, err := n.conn.Read(buf)

	if err != nil {
		return nil, err
	}

	if readNum != int(rspLen) {
		return nil, fmt.Errorf("cannot read all reply data: expected %d, read %d", request.Length, readNum)
	}

	reply, err := UnpackReplyFromData(buf)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func (n *NBD) sendCommand(command uint16, offset uint64, length uint32, data []byte) ([]byte, error) {
	handle := rand.Uint64()
	request := &NBDRequest{
		NBD_REQUEST_MAGIC,
		0,
		command,
		handle,
		offset,
		length,
		data,
	}

	reply, err := n.sendRequest(request)
	if err != nil {
		return nil, err
	}

	if reply.Magic != NBD_REPLY_MAGIC {
		return nil, errors.New("invalid reply magic")
	}

	if reply.Handle != handle {
		return nil, errors.New("invalid reply handle")
	}

	if reply.Error != 0 {
		return nil, fmt.Errorf("unknown reply error: code %x", reply.Error)
	}

	return reply.Data, nil
}

func (n *NBD) Read(offset uint64, length uint32) ([]byte, error) {
	return n.sendCommand(NBD_CMD_READ, offset, length, nil)
}

func (n *NBD) Write(offset uint64, data []byte) error {
	_, err := n.sendCommand(NBD_CMD_WRITE, offset, uint32(len(data)), data)
	return err
}
