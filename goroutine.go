package main

import (
	"fmt"
)

type userdetails struct {
	name    string
	age     int
	number  int
	address string
	zipcode int
}

func main() {
	msg := make(chan userdetails)
	go sendmessage(msg)
	user := <-msg
	fmt.Printf(" name=%s,\n age=%d,\n number=%d,\n address=%s,\n zipcode=%d\n", user.name, user.age, user.number, user.address, user.zipcode)
}

func sendmessage(ch chan<- userdetails) {
	Userdetails := userdetails{
		name:    "nitesh",
		age:     22,
		number:  9876543,
		address: "banjara hills",
		zipcode: 4321,
	}
	ch <- Userdetails
}
