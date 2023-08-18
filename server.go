package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/gomail.v2"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

const recaptchaServerName = "https://www.google.com/recaptcha/api/siteverify"

func verifyRecaptcha(response string, secret string) error {
	resp, err := http.PostForm(recaptchaServerName,
		url.Values{"secret": {secret}, "response": {response}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["success"] == false {
		return fmt.Errorf("reCAPTCHA verification failed")
	}
	return nil
}

func checkMissingFields(r *http.Request, expectedFields []string) []string {
	var missingFields []string

	for _, field := range expectedFields {
		if _, ok := r.Form[field]; !ok {
			missingFields = append(missingFields, field)
		}
	}

	return missingFields
}

func bookingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

		err := r.ParseMultipartForm(100 << 20)
		if err != nil {
			http.Error(w, "Failed to parse the form", http.StatusInternalServerError)
			return
		}

		// Loop through all form values and print
		for key, values := range r.PostForm {
			log.Printf("Field Name: %s", key)
			for _, value := range values {
				log.Printf("Value: %s", value)
			}
		}

		expectedFields := []string{"firstName", "lastName", "email", "idea", "pastClient", "size", "comment"}
		missingFields := checkMissingFields(r, expectedFields)

		if len(missingFields) > 0 {
			http.Error(w, fmt.Sprintf("Missing fields: %s", strings.Join(missingFields, ", ")), http.StatusBadRequest)
			return
		}

		captchaResponse := r.FormValue("g-recaptcha-response")
		captchaErr := verifyRecaptcha(captchaResponse, os.Getenv("CAPTCHA_SECRET"))
		if captchaErr != nil {
			http.Error(w, "reCAPTCHA verification failed", http.StatusUnauthorized)
			return
		}

		firstName := r.FormValue("firstName")
		lastName := r.FormValue("lastName")
		email := r.FormValue("email")
		idea := r.FormValue("idea")
		pastClient := r.FormValue("pastClient")
		size := r.FormValue("size")
		var day string
		days, ok := r.Form["day"]
		if ok {
			day = strings.Join(days, ", ")
		} else {
			log.Printf("No days selected: %v", err)
			http.Error(w, "No days selected", http.StatusBadRequest)
			return
		}

		placement, placementHeader, err := r.FormFile("placement")
		if err != nil {
			log.Printf("Error retrieving the placement image: %v", err)
			http.Error(w, "Error retrieving the placement image", http.StatusInternalServerError)
			return
		}
		defer placement.Close()

		reference1, reference1Header, err := r.FormFile("reference-1")
		if err != nil {
			log.Printf("Error retrieving the reference 1 image: %v", err)
			http.Error(w, "Error retrieving the reference 1 image", http.StatusInternalServerError)
			return
		}
		defer reference1.Close()

		reference2, reference2Header, err := r.FormFile("reference-2")
		if err != nil {
			log.Printf("Error retrieving the reference 2 image: %v", err)
			http.Error(w, "Error retrieving the reference 2 image", http.StatusInternalServerError)
			return
		}
		defer reference2.Close()

		reference3, reference3Header, err := r.FormFile("reference-3")
		if err != nil {
			log.Printf("Error retrieving the reference 3 image: %v", err)
			http.Error(w, "Error retrieving the reference 3 image", http.StatusInternalServerError)
			return
		}
		defer reference3.Close()

		comment := r.FormValue("comment")

		// Send the booking information via email.
		sendBookingEmail(firstName, lastName, email, pastClient, size, day, idea, comment, placementHeader.Filename, reference1Header.Filename, reference2Header.Filename, reference3Header.Filename, placement, reference1, reference2, reference3) // ... pass other collected data ...

		// Provide a response or redirect the user.
		http.ServeFile(w, r, "booking_confirmation.html")
	} else {
		http.ServeFile(w, r, "booking.html")
	}
}

func sendBookingEmail(firstName, lastName, email, pastClient, size, day, idea, comment, placementFilename, reference1Filename, reference2Filename, reference3Filename string, placement, reference1, reference2, reference3 multipart.File) {
	m := gomail.NewMessage()
	m.SetHeader("From", "bookings@studioabsent.com")
	m.SetHeader("To", "falcoderp@gmail.com")
	m.SetHeader("Subject", "New Booking Request")
	m.SetBody("text/plain", fmt.Sprintf("New booking from %s %s (%s)\nIdea: %s\nSize: %s\nDay: %s\nPast Client: %s\nComment: %s\n", firstName, lastName, email, idea, size, day, pastClient, comment)) // Update this format with other collected data.
	m.Attach(placementFilename, gomail.SetCopyFunc(func(w io.Writer) error {
		_, err := io.Copy(w, placement)
		return err
	}))
	m.Attach(reference1Filename, gomail.SetCopyFunc(func(w io.Writer) error {
		_, err := io.Copy(w, reference1)
		return err
	}))
	m.Attach(reference2Filename, gomail.SetCopyFunc(func(w io.Writer) error {
		_, err := io.Copy(w, reference2)
		return err
	}))
	m.Attach(reference3Filename, gomail.SetCopyFunc(func(w io.Writer) error {
		_, err := io.Copy(w, reference3)
		return err
	}))

	d := gomail.NewDialer("smtp.privateemail.com", 587, "bookings@studioabsent.com", os.Getenv("EMAIL_PASSWORD"))

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Failed to send booking email: %v", err)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {

	http.ServeFile(w, r, "admin.html")
}

func bioHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse the form data from the request body
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// Access form values
		content := r.PostFormValue("content")

		// Write content to bio_content.html
		err = os.WriteFile("bio_content.html", []byte(content), 0644)
		if err != nil {
			http.Error(w, "Failed to write to file", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Bio updated successfully.")
	} else {
		http.ServeFile(w, r, "bio_content.html")
	}
}

func bookingHeadingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse the form data from the request body
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// Iterate over all form values
		for key, values := range r.PostForm {
			fmt.Printf("Field Name: %s\n", key)
			for _, value := range values {
				fmt.Printf("Value: %s\n", value)
			}
		}
		// Access form values
		content := r.PostFormValue("content")
		fmt.Println(content)

		// Write content to bio_content.html
		err = os.WriteFile("booking_heading_content.html", []byte(content), 0644)
		if err != nil {
			http.Error(w, "Failed to write to file", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Booking heading updated successfully.")
	} else {
		http.ServeFile(w, r, "booking_heading_content.html")
	}
}

func availabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse the form data from the request body
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		htmlStr := ""

		days := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

		for _, day := range days {
			if _, exists := r.PostForm[day]; exists {
				htmlStr += fmt.Sprintf(`<label><input type="checkbox" name="day" value="%s">%s</input></label>`, day, day)
			}
		}
		if htmlStr != "" {
			htmlStr += fmt.Sprintf(`<label><input type="checkbox" name="day" value="Any day above">Any day above</label>`)
		}

		// Write content to bio_content.html
		err = os.WriteFile("availabilities_content.html", []byte(htmlStr), 0644)
		if err != nil {
			http.Error(w, "Failed to write to file", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Availabilities updated successfully.")
	} else {
		http.ServeFile(w, r, "availabilities_content.html")
	}
}

func footerHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "footer_content.html")
}

func headerHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "header_content.html")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the form data to make it available as a map
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse the form", http.StatusInternalServerError)
		return
	}

	// Extract the form data
	name := r.FormValue("name")
	email := r.FormValue("email")

	if email == "" {
		http.ServeFile(w, r, "footer_content.html")
	}

	data := map[string]interface{}{
		"Name":  name,
		"Email": email,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Failed to encode data", http.StatusInternalServerError)
		return
	}

	moosendAPIURL := fmt.Sprintf(
		"https://api.moosend.com/v3/subscribers/%s/subscribe.json?apikey=%s",
		os.Getenv("MOOSEND_LIST_ID"),
		os.Getenv("MOOSEND_API_KEY"))
	resp, err := http.Post(moosendAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to sign up to Moosend", http.StatusInternalServerError)
		return
	}

	if name == "" {
		fmt.Fprintf(w, "Thank you for signing up with %s!", email)
	} else {
		fmt.Fprintf(w, "Thank you %s for signing up with %s!", name, email)
	}
}

func BasicAuth(handler http.HandlerFunc, username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()

		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Please enter your username and password for this site"`)
			w.WriteHeader(401)
			w.Write([]byte("You are unauthorized to access the application.\n"))
			return
		}

		handler(w, r)
	}
}

func main() {
	err := godotenv.Load("./.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	username := os.Getenv("ADMIN_USERNAME")
	password := os.Getenv("ADMIN_PASSWORD")

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/booking", bookingHandler)

	http.HandleFunc("/admin", BasicAuth(adminHandler, username, password))
	http.HandleFunc("/update-bio", BasicAuth(bioHandler, username, password))
	http.HandleFunc("/update-booking-heading", BasicAuth(bookingHeadingHandler, username, password))
	http.HandleFunc("/update-availabilities", BasicAuth(availabilitiesHandler, username, password))

	http.HandleFunc("/bio", bioHandler)
	http.HandleFunc("/booking-heading", bookingHeadingHandler)
	http.HandleFunc("/footer", footerHandler)
	http.HandleFunc("/header", headerHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/availabilities", availabilitiesHandler)
	http.ListenAndServe(":7777", nil)
}
