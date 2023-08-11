package main

import (
	"fmt"
)

func main() {
	msg := make(chan string)
	go email(msg)
	mail := <-msg
	fmt.Println("the mail is sent")
	fmt.Println("the mail is received")
	fmt.Println(mail)
}

func email(ch chan string) {
	ch <- "hello nitesh"
}
