package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// / helper function to handle error
func checkErr(err error) { /// making a modifire func
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	//// step1 : genarate mnemonic
	entropy, err := bip39.NewEntropy(256) //genarate 256-bit entropy
	checkErr(err)

	mnemonic, err := bip39.NewMnemonic(entropy)
	checkErr(err)

	fmt.Println("mnemonic phrase:")
	fmt.Println(mnemonic)
	/// step 2 :genarate seed from mnemonic
	passphrase := "" //optionally, add a passphrase for extra security
	seed := bip39.NewSeed(mnemonic, passphrase)
	fmt.Println("\nSeed:", hex.EncodeToString(seed))
	////step 3 : Creat Master Key (BIP-32)
	masterKey, err := bip32.NewMasterKey(seed)
	checkErr(err)
	fmt.Println("\nMaster Private Key :", hex.EncodeToString(masterKey.Key))
	fmt.Println("\nMaster public Key :", hex.EncodeToString(masterKey.PublicKey().Key))
	////step[ 4 : drive child key (bip-44)
	//// path: m/44/0/0/0/0 (first btc address)
	path := []uint32{
		bip32.FirstHardenedChild + 44, //purpose : BIP-44
		bip32.FirstHardenedChild + 0,  // coin Type : Bitcoin
		bip32.FirstHardenedChild + 0,  // account : 0
		0,                             // change : (external addresses)
		0,                             // address Index : 0
	}
	currentKey := masterKey
	for _, index := range path {
		currentKey, err = currentKey.NewChildKey(index)
		checkErr(err)
	}
	fmt.Println("\nDerived Private Key (First Address):", hex.EncodeToString(currentKey.Key))
	fmt.Println("\nDerived Public Key (First Address):", hex.EncodeToString(currentKey.PublicKey().Key))

}
