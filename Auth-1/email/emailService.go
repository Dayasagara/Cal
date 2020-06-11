package email

import (
	"fmt"
	"net/smtp"
)

func RegistrationMail() {

	hostURL := "smtp.gmail.com"
	hostPort := "587"
	emailSender := "@gmail.com"
	fmt.Print("Provide password for " + emailSender + " : \n")
	var password string

	//taking password as input from console
	fmt.Scan(&password)
	emailReceiver := "@gmail.com"

	//PlainAuth:-returned Auth uses the given username and password to authenticate to host and act as identity
	emailAuth := smtp.PlainAuth(
		"",
		emailSender,
		password,
		hostURL,
	)

	//The msg headers should usually include fields such as 
	//"From", "To", "Subject", and "Cc".
	// Sending "Bcc" messages is accomplished by 
	//including an email address in the to parameter 
	//but not including it in the msg headers

	msg := []byte("To: " + emailReceiver + "\r\n" +
		"Subject: " + "Hi" + "\r\n" + "Welcome")

	//func SendMail(addr string, a Auth, from string, to []string, msg []byte) error
	//SendMail connects to the server at addr,
	//switches to TLS if possible, 
	//authenticates with the optional mechanism a if possible,
	//and then sends an email from address from, 
	//to addresses to, with message msg. 
	//The addr must include a port, as in "mail.example.com:smtp"
	
	err := smtp.SendMail(
		hostURL+":"+hostPort,
		emailAuth,
		emailSender,
		[]string{emailReceiver},
		msg)

	if err != nil {
		fmt.Print("Error :", err)
	} else {
		fmt.Print("Email sent")
	}
}
