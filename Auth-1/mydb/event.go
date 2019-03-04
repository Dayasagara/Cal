package mydb

import (
	"log"
	"database/sql"
	"fmt"
	"os"
)

type Event struct {
	id     string   
	subject  string	
	StartDateTime string		
	EndDateTime  string	
	location string
	description string
}

//Insert event details into database
func AddEvent(id,name,date,time,description,location string) (int){
	_,err := db.Exec(`
		INSERT INTO public."events" ("ID","SUBJECT","STARTDATETIME","ENDDATETIME","DESCRIPTION","LOCATION")
		VALUES ($1,$2,$3,$4,$5,$6)`,id,name,date,time,description,location)
	
	if err != nil {
		log.Printf("Insertion Error : %v",err)
		return 1
	}else{
		log.Printf("Added successfully")
		return 0
	}
	
}
//Create an ics file from the event details in the database
func GetEventByID(id string) (*Event, error) {
	result := &Event{}
	row := db.QueryRow(`
		SELECT "ID","SUBJECT","STARTDATETIME","ENDDATETIME","DESCRIPTION","LOCATION"
		FROM public."events"
		WHERE "ID" = $1`, id)
	err := row.Scan(&result.id, &result.subject, &result.StartDateTime,&result.EndDateTime,&result.description,&result.location)
	if err!=nil{
		log.Printf("Error:%v",err)
	}else{
		var file, err1 = os.Create(`calendar1.ics`)
		defer file.Close()
		fmt.Fprintf(file,"BEGIN:VCALENDAR\nMETHOD:PUBLISH\nVERSION:2.0\nPRODID:-//Company Name//Product//Language\nBEGIN:VEVENT")
        fmt.Fprintf(file,"\nSUMMARY:")
        fmt.Fprintf(file,result.subject)
        fmt.Fprintf(file,"\nDTSTART:")
        fmt.Fprintf(file,result.StartDateTime)
        fmt.Fprintf(file,"\nDTEND:")
        fmt.Fprintf(file,result.EndDateTime)
        fmt.Fprintf(file,"\nDESCRIPTION:")
        fmt.Fprintf(file,result.description)
        fmt.Fprintf(file,"\nLOCATION:")
        fmt.Fprintf(file,result.location)
		fmt.Fprintf(file,"\nEND:VEVENT\nEND:VCALENDAR")   
		if err1 != nil {
            fmt.Println(err1)
        } 
	}
	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("No event found")
	case err != nil:
		
		return nil, err
	}
	return result, nil
}

