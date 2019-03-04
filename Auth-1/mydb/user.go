package mydb

import (
	"log"
	"database/sql"
	"fmt"
	"crypto/sha512"
	"encoding/base64"
)

type User struct {
	email     string 
	password  string 
	username string  
}

func CreateTable() (error,error) {
	flag := 0
	_,err1 := db.Exec(`
	CREATE TABLE public."user"
(
    "USERNAME" character varying(255) COLLATE pg_catalog."default" NOT NULL,
    "EMAIL" character varying(255) COLLATE pg_catalog."default",
    "PASSWORD" character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT user_pkey PRIMARY KEY ("USERNAME")
)`)
	if err1 != nil {
		log.Printf("Creation Error : %v",err1)
		flag++
	}else{
		log.Printf("Table Created successfully") 
	}
	_,err := db.Exec(`
	CREATE TABLE public."events"(
    "ID" text COLLATE pg_catalog."default" NOT NULL,
    "SUBJECT" text COLLATE pg_catalog."default" NOT NULL,
    "STARTDATETIME" timestamp with time zone,
    "ENDDATETIME" timestamp with time zone,
    "DESCRIPTION" text COLLATE pg_catalog."default",
    "LOCATION" text COLLATE pg_catalog."default"
)`)
	if err != nil {
		log.Printf("Creation Error : %v",err)
		flag++
	}else{
		log.Printf("Table Created successfully") 
	}
	return err1,err
}

//Signup, Inserting user details into the database 
func Signup(username, email, password string) int{
	hasher := sha512.New()
	hasher.Write([]byte(password))
	pwd := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	_,err := db.Exec(`
		INSERT INTO public."user" ("USERNAME", "EMAIL", "PASSWORD")
		VALUES ($1,$2,$3)`,username, email, pwd)
	
	if err != nil {
		log.Printf("Insertion Error : %v",err)
		return 0
	}else{
		log.Printf("Registered successfully")
		return 1 
	}
}
//Login 
func Login(email, password string) (*User, error) {
	result := &User{}
	hasher := sha512.New()
	hasher.Write([]byte(password))
	pwd := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	row := db.QueryRow(`
		SELECT "USERNAME", "EMAIL", "PASSWORD"
		FROM public."user"
		WHERE "EMAIL" = $1 
		  AND "PASSWORD" = $2`, email, pwd)
	err := row.Scan(&result.username, &result.email, &result.password)
	if err != nil {
		log.Printf("Error:%v",err)
	}
	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("User not found")
	case err != nil:
		return nil, err
	}
	return result, nil
}

//ChangePassword
func ChangePassword(email,oldPassword,newPassword string) int {
	result := &User{}
	hasher := sha512.New()
	hasher.Write([]byte(oldPassword))
	pwd := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	row := db.QueryRow(`
		SELECT "PASSWORD" FROM public."user" WHERE "EMAIL"=$1`,email)
	err1 := row.Scan(&result.password)	
	if err1 != nil{
		log.Printf("Error:%v",err1)
	} 
	if(result.password==pwd){
		hasher1 := sha512.New()
		hasher1.Write([]byte(newPassword))
		pwd1 := base64.URLEncoding.EncodeToString(hasher1.Sum(nil))
		_,err := db.Exec(`
		UPDATE public."user" SET "PASSWORD"=$1
		WHERE "EMAIL"=$2`,pwd1,email)
		if err != nil {
			log.Printf("Updation Error : %v",err)
			return 0
		}else{
			log.Printf("Updated successfully")
			return 1
		}
	}
	return 2
}