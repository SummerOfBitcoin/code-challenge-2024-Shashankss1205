package main

import (
	"encoding/hex"
	"encoding/binary"
	"encoding/json"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"github.com/mr-tron/base58"
	"github.com/btcsuite/btcutil/bech32"
)




type BlockHeader struct {
	Version       uint32
	PrevBlockHash string
	MerkleRoot    string
	Time          int64
	Bits          uint32
	Nonce         uint32
}


type Input struct {
	TxID         string   `json:"txid"`
	Vout         uint32   `json:"vout"`
	Prevout      Prevout  `json:"prevout"`
	Scriptsig    string   `json:"scriptsig"`
	ScriptsigAsm string   `json:"scriptsig_asm"`
	Witness      []string `json:"witness"`
	IsCoinbase   bool     `json:"is_coinbase"`
	Sequence     uint32   `json:"sequence"`
}

type Prevout struct {
	Scriptpubkey        string `json:"scriptpubkey"`
	ScriptpubkeyAsm     string `json:"scriptpubkey_asm"`
	ScriptpubkeyType    string `json:"scriptpubkey_type"`
	ScriptpubkeyAddress string `json:"scriptpubkey_address"`
	Value               uint64 `json:"value"`
}

type Transaction struct {
	Version  uint32    `json:"version"`
	Locktime uint32    `json:"locktime"`
	Vin      []Input   `json:"vin"`
	Vout     []Prevout `json:"vout"`
}

type TxInfo struct {
	TxID   string
	WTxID  string
	Fee    uint64
	Weight uint64
}
type TxWeight struct {
	BaseSize    int `json:"base_size"`    // Size of non-witness data in bytes
	WitnessSize int `json:"witness_size"` // Size of witness data in bytes
	Weight      int `json:"weight"`       // Total weight in weight units
}


type MerkleNode struct {
	Left  *MerkleNode
	Data  []byte
	Right *MerkleNode
}

type MerkleTree struct {
	MerkleRoot *MerkleNode
}

const target string = "0000ffff00000000000000000000000000000000000000000000000000000000"

func CompareByteArrays(a, b []byte) int {
	if len(a) != len(b) {
		panic("Arrays must have the same length")
	}

	for i := range a {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}

	return 0
}

func ProofOfWork(bh *BlockHeader) bool {
	targetBytes, _ := hex.DecodeString(target)
	// fmt.Printf("Target: %v\n", targetBytes)
	for {
		serialized := SerializeBlockHeader(bh)
		hash := ReverseBytes(To_sha(To_sha(serialized)))

		if CompareByteArrays(hash, targetBytes) == -1 {
			fmt.Println("Block Mined", hex.EncodeToString(hash))
			return true
		}
		if bh.Nonce < 0x0 || bh.Nonce > 0xffffffff {
			fmt.Println("Block can not be mined")
			return false
		}
		bh.Nonce++
	}
}


var Bh BlockHeader = BlockHeader{
	Version:       7,
	PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
	MerkleRoot:    "",
	Time:          time.Now().Unix(),
	Bits:          0x1f00ffff,
	Nonce:         0,
}

func MineBlock() {
	netReward, TxIDs, _ := Prioritize()

	cbTx := CreateCoinbase(netReward)
	serializedcbTx, _ := SerializeTransaction(cbTx)
	fmt.Printf("CBTX: %x\n", serializedcbTx)
	TxIDs = append([]string{hex.EncodeToString(ReverseBytes(To_sha(To_sha(serializedcbTx))))}, TxIDs...)
	mkr := NewMerkleTree(TxIDs)
	Bh.MerkleRoot = hex.EncodeToString(mkr.Data)
	cbtxbase := CalculateBaseSize(cbTx)
	cbtxwitness := CalculateWitnessSize(cbTx)
	fmt.Println("Cbtx wt: ", cbtxwitness+(cbtxbase*4))
	if ProofOfWork(&Bh) {
		file, _ := os.Create("output.txt")
		defer file.Close()
		// fmt.Println(Bh.merkleRoot)
		// fmt.Println(Bh.nonce)
		serializedBh := SerializeBlockHeader(&Bh)
		segserialized, _ := SegWitSerialize(cbTx)
		file.WriteString(hex.EncodeToString(serializedBh) + "\n")
		file.WriteString(hex.EncodeToString(segserialized) + "\n")
		for _, tx := range TxIDs {
			file.WriteString(tx + "\n")
		}
	}
}




func CreateCoinbase(netReward uint64) *Transaction {
	witnessCommitment := CreateWitnessMerkle()
	coinbaseTx := Transaction{
		Version: 1,
		Vin: []Input{
			{
				TxID: "0000000000000000000000000000000000000000000000000000000000000000",
				Vout: 0xffffffff,
				Prevout: Prevout{
					Scriptpubkey:        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
					ScriptpubkeyAsm:     "0014df4bf9f3621073202be59ae590f55f42879a21a0",
					ScriptpubkeyType:    "p2pkh",
					ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
					Value:               uint64(netReward),
				},
				IsCoinbase: true,
				Sequence:   0xffffffff,
				Scriptsig:  "03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
				Witness:    []string{"0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
		Vout: []Prevout{
			{
				Scriptpubkey:        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
				ScriptpubkeyAsm:     "0014df4bf9f3621073202be59ae590f55f42879a21a0",
				ScriptpubkeyType:    "p2pkh",
				ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
				Value:               uint64(netReward),
			},
			{
				Scriptpubkey:        "6a24" + "aa21a9ed" + witnessCommitment, //OPRETURN +OP_PUSHBYTES_36+ commitment header + witnessCommitment
				ScriptpubkeyAsm:     "OP_RETURN" + "OP_PUSHBYTES_36" + "aa21a9ed" + witnessCommitment,
				ScriptpubkeyType:    "op_return",
				ScriptpubkeyAddress: "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c",
				Value:               uint64(0),
			},
		},
		Locktime: 0,
	}
	return &coinbaseTx
}

func NewMerkleNode(lnode *MerkleNode, rnode *MerkleNode, data []byte) *MerkleNode {
	var mNode MerkleNode = MerkleNode{}
	if lnode == nil && rnode == nil {
		//hash256 of the data
		mNode.Data = ReverseBytes(data)
	} else {
		var prevHash []byte = append(lnode.Data, rnode.Data...)
		mNode.Data = To_sha(To_sha(prevHash))
	}
	mNode.Left = lnode
	mNode.Right = rnode
	return &mNode
}

func NewMerkleTree(leaves []string) *MerkleNode {
	var nodes []MerkleNode

	for _, leaf := range leaves {
		data, _ := hex.DecodeString(leaf)
		var node MerkleNode = *NewMerkleNode(nil, nil, data)
		nodes = append(nodes, node)
	}

	for len(nodes) > 1 {
		var newLevel []MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			// Handle case where the total number of nodes is odd.
			if len(nodes)%2 != 0 {
				nodes = append(nodes, nodes[len(nodes)-1])
			}
			node := *NewMerkleNode(&nodes[i], &nodes[i+1], nil)
			newLevel = append(newLevel, node)
		}
		nodes = newLevel
	}
	return &nodes[0]

}

func CreateWitnessMerkle() string {
	_, _, wTxIDs := Prioritize()
	wTxIDs = append([]string{"0000000000000000000000000000000000000000000000000000000000000000"}, wTxIDs...)
	merkleRoot := NewMerkleTree(wTxIDs)
	fmt.Println("WMKR: ", hex.EncodeToString(merkleRoot.Data))
	commitment_string := hex.EncodeToString(merkleRoot.Data) + "0000000000000000000000000000000000000000000000000000000000000000"
	WitnessCommitment, _ := hex.DecodeString(commitment_string)
	WitnessCommitment = To_sha(To_sha(WitnessCommitment))
	fmt.Println("Witness Commitment: ", hex.EncodeToString(WitnessCommitment))
	return hex.EncodeToString(WitnessCommitment)
}

func Comp(a, b TxInfo) bool {
	return float64(a.Fee)/float64(a.Weight) > float64(b.Fee)/float64(b.Weight)
}
func Prioritize() (uint64, []string, []string) {
	var permittedTxIDs []string
	var permittedWTxIDs []string
	dir := "./mempool"
	files, _ := os.ReadDir(dir)
	var txInfo []TxInfo
	for _, file := range files {
		txData, err := JsonData(dir + "/" + file.Name())
		Handle(err)
		var tx Transaction
		err = json.Unmarshal([]byte(txData), &tx)
		var fee uint64 = 0
		for _, vin := range tx.Vin {
			fee += vin.Prevout.Value
		}
		for _, vout := range tx.Vout {
			fee -= vout.Value
		}
		serialized, _ := SerializeTransaction(&tx)
		segserialized, _ := SegWitSerialize(&tx)
		txID := ReverseBytes(To_sha(To_sha(serialized)))
		wtxID := ReverseBytes(To_sha(To_sha(segserialized)))
		txInfo = append(txInfo, TxInfo{TxID: hex.EncodeToString(txID), WTxID: hex.EncodeToString(wtxID), Fee: fee, Weight: uint64(CalculateWitnessSize(&tx) + CalculateBaseSize(&tx)*4)})

	}
	sort.Slice(txInfo, func(i, j int) bool {
		return Comp(txInfo[i], txInfo[j])
	})
	var PermissibleTxs []TxInfo
	var PermissibleWeight uint64 = 3999300
	var reward uint64 = 0
	for _, tx := range txInfo {
		if PermissibleWeight >= tx.Weight {
			PermissibleTxs = append(PermissibleTxs, tx)
			PermissibleWeight -= tx.Weight
			permittedTxIDs = append(permittedTxIDs, tx.TxID)
			permittedWTxIDs = append(permittedWTxIDs, tx.WTxID)
			reward += tx.Fee
		}
	}
	fmt.Println("weight: ", PermissibleWeight)
	fmt.Println("reward: ", reward)
	return reward, permittedTxIDs, permittedWTxIDs
}



func Uint16ToBytes(n uint16) []byte {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, n)
	return bytes
}
func Uint32ToBytes(n uint32) []byte {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, n)
	return bytes
}

func Uint64ToBytes(n uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, n)
	return bytes
}

func ReverseBytes(data []byte) []byte {
	length := len(data)
	for i := 0; i < length/2; i++ {
		data[i], data[length-i-1] = data[length-i-1], data[i]
	}
	return data
}

func SerializeVarInt(n uint64) []byte {
	if n < 0xfd {
		return []byte{byte(n)}
	} else if n <= 0xffff {
		return append([]byte{0xfd}, Uint16ToBytes(uint16(n))...)
	} else if n <= 0xffffffff {
		return append([]byte{0xfe}, Uint32ToBytes(uint32(n))...)
	} else {
		return append([]byte{0xff}, Uint64ToBytes(n)...)
	}
}

func SerializeTransaction(tx *Transaction) ([]byte, error) {

	var serialized []byte
	// Serialize version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, tx.Version)
	serialized = append(serialized, versionBytes...)
	// Serialize vin count
	vinCount := uint64(len(tx.Vin))
	serialized = append(serialized, SerializeVarInt(vinCount)...)

	// Serialize vin
	for _, vin := range tx.Vin {
		txidBytes, _ := hex.DecodeString(vin.TxID)
		serialized = append(serialized, ReverseBytes(txidBytes)...)

		voutBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(voutBytes, vin.Vout)
		serialized = append(serialized, voutBytes...)

		Scriptsig_bytes, _ := hex.DecodeString(vin.Scriptsig)
		length_scriptsig := (uint64(len(Scriptsig_bytes)))
		serialized = append(serialized, SerializeVarInt(length_scriptsig)...)

		serialized = append(serialized, Scriptsig_bytes...)

		// Serialize sequence
		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, vin.Sequence)
		serialized = append(serialized, sequenceBytes...)

	}

	// Serialize vout count
	voutCount := uint64(len(tx.Vout))
	serialized = append(serialized, SerializeVarInt(voutCount)...)

	// Serialize vout
	for _, vout := range tx.Vout {
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, vout.Value)
		serialized = append(serialized, valueBytes...)

		// Serialize scriptPubKey length
		scriptPubKeyBytes, err := hex.DecodeString(vout.Scriptpubkey)
		scriptPubKeyLen := uint64(len(scriptPubKeyBytes)) // Divide by 2 if appending the length of the non decoded form to get byte length since scriptPubKey is hex encoded
		serialized = append(serialized, SerializeVarInt(scriptPubKeyLen)...)

		// Serialize scriptPubKey
		if err != nil {
			return nil, err
		}
		serialized = append(serialized, scriptPubKeyBytes...)
	}
	//Locktime
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)
	serialized = append(serialized, locktimeBytes...)

	return serialized, nil
}
func SegWitSerialize(tx *Transaction) ([]byte, error) {

	var serialized []byte
	isSegwit := CheckSegWit(tx)
	// Serialize version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, tx.Version)
	serialized = append(serialized, versionBytes...)
	// Serialize vin count
	if isSegwit {
		serialized = append(serialized, []byte{0x00, 0x01}...)
	}
	vinCount := uint64(len(tx.Vin))
	serialized = append(serialized, SerializeVarInt(vinCount)...)

	// Serialize vin
	for _, vin := range tx.Vin {
		txidBytes, _ := hex.DecodeString(vin.TxID)
		serialized = append(serialized, ReverseBytes(txidBytes)...)

		voutBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(voutBytes, vin.Vout)
		serialized = append(serialized, voutBytes...)

		Scriptsig_bytes, _ := hex.DecodeString(vin.Scriptsig)
		length_scriptsig := (uint64(len(Scriptsig_bytes)))
		serialized = append(serialized, SerializeVarInt(length_scriptsig)...)

		serialized = append(serialized, Scriptsig_bytes...)

		// Serialize sequence
		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, vin.Sequence)
		serialized = append(serialized, sequenceBytes...)

	}

	// Serialize vout count
	voutCount := uint64(len(tx.Vout))
	serialized = append(serialized, SerializeVarInt(voutCount)...)

	// Serialize vout
	for _, vout := range tx.Vout {
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, vout.Value)
		serialized = append(serialized, valueBytes...)

		// Serialize scriptPubKey length
		scriptPubKeyBytes, err := hex.DecodeString(vout.Scriptpubkey)
		scriptPubKeyLen := uint64(len(scriptPubKeyBytes)) // Divide by 2 if appending the length of the non decoded form to get byte length since scriptPubKey is hex encoded
		serialized = append(serialized, SerializeVarInt(scriptPubKeyLen)...)

		// Serialize scriptPubKey
		if err != nil {
			return nil, err
		}
		serialized = append(serialized, scriptPubKeyBytes...)
	}
	//Locktime
	if isSegwit {
		for _, vin := range tx.Vin {
			witnessCount := uint64(len(vin.Witness))
			serialized = append(serialized, SerializeVarInt(witnessCount)...)
			for _, witness := range vin.Witness {
				witnessBytes, _ := hex.DecodeString(witness)
				witnessLen := uint64(len(witnessBytes))
				serialized = append(serialized, SerializeVarInt(witnessLen)...)
				serialized = append(serialized, witnessBytes...)
			}
		}
	}
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)
	serialized = append(serialized, locktimeBytes...)
	return serialized, nil
}

func SerializeBlockHeader(bh *BlockHeader) []byte {
	var serialized []byte

	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, bh.Version)
	serialized = append(serialized, versionBytes...)

	prevBlockHashbytes, _ := hex.DecodeString(bh.PrevBlockHash)
	serialized = append(serialized, prevBlockHashbytes...)

	merkleRootbytes, _ := hex.DecodeString(bh.MerkleRoot)
	serialized = append(serialized, merkleRootbytes...)

	bh.Time = time.Now().Unix()
	timeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(timeBytes, uint32(bh.Time))
	serialized = append(serialized, timeBytes...)

	bitsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bitsBytes, bh.Bits)
	serialized = append(serialized, bitsBytes...)

	NonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(NonceBytes, bh.Nonce)
	serialized = append(serialized, NonceBytes...)

	return serialized
}


func ExtractHexFromScriptpubkeyAsm(str []string) string {
	for i := 0; i < len(str); i++ {
		if str[i] == "OP_PUSHBYTES_20" || str[i] == "OP_PUSHBYTES_32" {
			return str[i+1]
		}
	}
	return ""
}

func Base58Encode(input []byte) []byte {
	var encoded string = base58.Encode(input)
	return []byte(encoded)
}

func To_sha(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func JsonData(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Handle(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func CheckSegWit(tx *Transaction) bool {
	for _, vin := range tx.Vin {
		if len(vin.Witness) > 0 {
			return true
		}
	}
	return false
}


func CalculateBaseSize(tx *Transaction) int {
	serialised, _ := SerializeTransaction(tx)
	return len(serialised)
}

// Function to calculate witness size
func CalculateWitnessSize(tx *Transaction) int {
	if !CheckSegWit(tx) {
		return 0

	}
	// Inputs (witness)
	var serialized []byte
	isSegwit := CheckSegWit(tx)
	if isSegwit {
		serialized = append(serialized, []byte{0x00, 0x01}...)
	}
	if isSegwit {
		for _, vin := range tx.Vin {
			witnessCount := uint64(len(vin.Witness))
			serialized = append(serialized, SerializeVarInt(witnessCount)...)
			for _, witness := range vin.Witness {
				witnessBytes, _ := hex.DecodeString(witness)
				witnessLen := uint64(len(witnessBytes))
				serialized = append(serialized, SerializeVarInt(witnessLen)...)
				serialized = append(serialized, witnessBytes...)
			}
		}
	}
	return len(serialized)
}



var (
	ct_p2pkh  = 0
	ct_p2sh   = 0
	ct_p2wpkh = 0
	ct_p2wsh  = 0
)

func Address() {
	dir := "./mempool"
	files, err := os.ReadDir(dir)
	Handle(err)
	for _, file := range files {
		txData, err := JsonData(dir + "/" + file.Name())
		Handle(err)
		var tx Transaction
		err = json.Unmarshal([]byte(txData), &tx)
		Handle(err)
		for _, vin := range tx.Vin {
			if vin.Prevout.ScriptpubkeyType == "p2pkh" {
				pubkey_asm := vin.Prevout.ScriptpubkeyAsm
				address := P2pkh(pubkey_asm)
				if string(address) == vin.Prevout.ScriptpubkeyAddress {
					// fmt.Println(vin.Prevout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2pkh++
					continue
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vin.Prevout.ScriptpubkeyAddress)
				}
			}

			if vin.Prevout.ScriptpubkeyType == "p2sh" {
				pubkey_asm := vin.Prevout.ScriptpubkeyAsm
				address := P2sh(pubkey_asm)
				if string(address) == vin.Prevout.ScriptpubkeyAddress {
					// fmt.Println(vin.Prevout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2sh++
					continue
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vin.Prevout.ScriptpubkeyAddress)
				}
			}

			if vin.Prevout.ScriptpubkeyType == "v0_p2wpkh" {
				pubkey_asm := vin.Prevout.ScriptpubkeyAsm
				address := P2wpkh(pubkey_asm)
				if string(address) == vin.Prevout.ScriptpubkeyAddress {
					// fmt.Println(vin.Prevout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2wpkh++
					continue
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vin.Prevout.ScriptpubkeyAddress)
				}
			}

			if vin.Prevout.ScriptpubkeyType == "v0_p2wsh" {
				pubkey_asm := vin.Prevout.ScriptpubkeyAsm
				address := P2wsh(pubkey_asm)
				if string(address) == vin.Prevout.ScriptpubkeyAddress {
					// fmt.Println(vin.Prevout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2wsh++
					continue
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vin.Prevout.ScriptpubkeyAddress)
				}
			}
		}
		for _, vout := range tx.Vout {
			if vout.ScriptpubkeyType == "p2pkh" {
				pubkey_asm := vout.ScriptpubkeyAsm
				address := P2pkh(pubkey_asm)
				if string(address) == vout.ScriptpubkeyAddress {
					// fmt.Println(vout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2pkh++
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vout.ScriptpubkeyAddress)
				}
			}

			if vout.ScriptpubkeyType == "p2sh" {
				pubkey_asm := vout.ScriptpubkeyAsm
				address := P2sh(pubkey_asm)
				if string(address) == vout.ScriptpubkeyAddress {
					// fmt.Println(vout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2sh++
					continue
				} else {
					fmt.Println("Address not matched")
					fmt.Println("Address: ", address)
					fmt.Println("Scriptpubkey Address: ", vout.ScriptpubkeyAddress)
				}
			}

			if vout.ScriptpubkeyType == "v0_p2wpkh" {
				pubkey_asm := vout.ScriptpubkeyAsm
				address := P2wpkh(pubkey_asm)
				if string(address) == vout.ScriptpubkeyAddress {
					// fmt.Println(vout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2wpkh++
				} else {
					fmt.Println("Address not matched")
					fmt.Printf("Address: %s\n", address)
					fmt.Println("Scriptpubkey Address: ", vout.ScriptpubkeyAddress)
				}
			}

			if vout.ScriptpubkeyType == "v0_p2wsh" {
				pubkey_asm := vout.ScriptpubkeyAsm
				address := P2wsh(pubkey_asm)
				if string(address) == vout.ScriptpubkeyAddress {
					// fmt.Println(vout.ScriptpubkeyAddress)
					// fmt.Printf(" %s\n", address)
					ct_p2wsh++
				} else {
					fmt.Println("Address not matched")
					fmt.Printf("Address: %s\n", address)
					fmt.Println("Scriptpubkey Address: ", vout.ScriptpubkeyAddress)
				}
			}
		}
	}
	fmt.Println("Count of p2pkh address matched: ", ct_p2pkh)
	fmt.Println("Count of p2sh address matched: ", ct_p2sh)
	fmt.Println("Count of p2wpkh address matched: ", ct_p2wpkh)
	fmt.Println("Count of p2wpkh address matched: ", ct_p2wsh)
}


const (
	versionByte string = "00"
)

func P2pkh(scriptpubkey_asm string) []byte {
	str := strings.Split(scriptpubkey_asm, " ")

	pubkeyhash := ExtractHexFromScriptpubkeyAsm(str)
	// Convert hex to bytes)
	pubkeyhash_bytes, _ := hex.DecodeString(pubkeyhash)
	versionByte_bytes, _ := hex.DecodeString(versionByte)

	version_pubkeyhash := append(versionByte_bytes, pubkeyhash_bytes...)

	checksum := To_sha(To_sha(version_pubkeyhash))

	appended_checksum := append(version_pubkeyhash, checksum[:4]...)

	address := Base58Encode(appended_checksum)

	return address

}

func P2sh(scriptpubkey_asm string) []byte {
	hashed_script := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	hashed_script_bytes, _ := hex.DecodeString(hashed_script)
	versionByte_bytes, _ := hex.DecodeString("05")
	version_hash := append(versionByte_bytes, hashed_script_bytes...)

	checksum := To_sha(To_sha(version_hash))

	appended_checksum := append(version_hash, checksum[:4]...)

	address := Base58Encode(appended_checksum)

	return address

}



func P2wpkh(scriptpubkey_asm string) []byte {

	pubkeyHash := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " ")) //or the witness program
	version := "00"

	pubkeyHashBytes, _ := hex.DecodeString(pubkeyHash)
	versionBytes, err := hex.DecodeString(version)

	conv, err := bech32.ConvertBits(pubkeyHashBytes, 8, 5, true)
	Handle(err)

	versionPubkeyHash := append(versionBytes, conv...)
	address, err := bech32.Encode("bc", versionPubkeyHash)
	Handle(err)
	return []byte(address)

}

func P2wsh(scriptpubkey_asm string) []byte {
	witness_scriptHash := ExtractHexFromScriptpubkeyAsm(strings.Split(scriptpubkey_asm, " "))
	witness_scriptHash_bytes, _ := hex.DecodeString(witness_scriptHash)
	version := "00"
	version_bytes, _ := hex.DecodeString(version)

	conv, _ := bech32.ConvertBits(witness_scriptHash_bytes, 8, 5, true)
	conv = append(version_bytes, conv...)

	hrp := "bc"
	encodedAddress, _ := bech32.Encode(hrp, conv)
	return []byte(encodedAddress)
}


func main() {
	MineBlock()
}

