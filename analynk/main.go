package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

type PlatformData struct {
	Platforms []Platform `json:"platforms"`
}
type Platform struct {
	Platform string `json:"platform"`
	SID      string `json:"sid"`
}
type JbxErrorObject struct {
	Errors []JbxErr `json:"errors"`
}
type JbxErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type JbxResponseObject struct {
	Data JbxData `json:"data"`
}
type JbxData struct {
	ID string `json:"submission_id"`
}
type VtErrorObject struct {
	Error VtErr `json:"error"`
}
type VtErr struct {
	Code    string    `json:"code"`
	Message string `json:"message"`
}
type VtResponseObject struct {
	Data VtData `json:"data"`
}
type VtData struct {
	ID string `json:"id"`
}

type VtAnalysisData struct {
	Data _Vt `json:"data"`
}
type _Vt struct {
	Attributes VtAnalysis `json:"attributes"`
}
type VtAnalysis struct {
	LAS Last_Analysis_Stats `json:"last_analysis_stats"`
}
type Last_Analysis_Stats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
}
type JbxAnalysisData struct {
	Data JbxAnalysis `json:"data"`
}
type JbxAnalysis struct {
	MRA    MRA    `json:"most_relevant_analysis"`
	Status string `json:"status"`
}
type MRA struct {
	Detection string `json:"detection"`
	Score     int    `json:"score"`
}

var (
	app           = kingpin.New("analynk", "URL analyser application")
	analyse       = app.Command("analyse", "Analyse URL on VT and JoeSecurity threat intelligence platforms")
	jbxApiKey     = app.Flag("jbx-key", "API key for joesecurity").Required().String()
	vtApiKey      = app.Flag("vt-key", "API key for VirusTotal").Required().String()
	_site         = analyse.Flag("url", "URL to analyse on VT / Jbxcloud").Short('u').Required().String()
	check_results = app.Command("check-results", "View results of a recent analysis")
	_analysedSite = check_results.Flag("url", "Analysed URL to view results for").Short('u').Required().String()

	jbxEndpoint = "https://jbxcloud.joesecurity.org/api/v2/submission/new"
	vtEndpoint  = "https://www.virustotal.com/api/v3/urls"

	jbxResultsEP = "https://jbxcloud.joesecurity.org/api/v2/submission/info"
)

const (
	Red    = "\033[0;31m"
	Yellow = "\033[33m"
	Green  = "\033[32m"
	Reset  = "\033[0m"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors: true,
	})
	c := kingpin.MustParse(app.Parse(os.Args[1:]))
	site := strings.TrimSuffix(*_site, "/")
	analysedSite := strings.TrimSuffix(*_analysedSite, "/")

SWITCH:
	switch c {
	case analyse.FullCommand():
		if _, err := url.ParseRequestURI(site); err != nil {
			log.Fatal(err)
		}
		fileName, _ := getConfigFileName(site)
		confPath := "analysis/" + fileName
		if _, err := os.Stat(confPath); !os.IsNotExist(err) {
			log.Infof("%sPrevious analysis of this URL found. Checking results...%s", Yellow, Reset)
			c = check_results.FullCommand()
			analysedSite = site
			goto SWITCH
		}
		var jbxValues = map[string]io.Reader{
			"apikey":     strings.NewReader(*jbxApiKey),
			"url":        strings.NewReader(site),
			"accept-tac": strings.NewReader("1"),
		}
		var vtValues = url.Values{
			"url": {site},
		}
		if err := jbxAnalyse(site, jbxEndpoint, jbxValues); err != nil {
			log.Errorf("Error analysing link with Jbxcloud: %v", err)
		}
		if err := vtAnalyse(site, vtEndpoint, *vtApiKey, vtValues); err != nil {
			log.Errorf("Error analysing link with VirusTotal: %v", err)
		}
	case check_results.FullCommand():
		if _, err := url.ParseRequestURI(analysedSite); err != nil {
			log.Fatal(err)
		}
		var jbxValues = map[string]io.Reader{
			"apikey": strings.NewReader(*jbxApiKey),
		}
		if err := jbxResults(analysedSite, *jbxApiKey, jbxResultsEP, jbxValues); err != nil {
			log.Errorf("Error getting JBX analysis results: %v", err)
		}
		if err := vtResults(analysedSite, *vtApiKey, vtEndpoint); err != nil {
			log.Errorf("Error getting VirusTotal analysis results: %v", err)
		}
	}
}

func jbxResults(aUrl, api_key, endpoint string, values map[string]io.Reader) error {

	sid, err := getSubmissionID("jbx", aUrl)
	if err != nil {
		return fmt.Errorf("Error fetching JBX submission ID: %v", err)
	}
	log.Infof("retrieved SID: %s", sid)
	values["submission_id"] = strings.NewReader(sid)
	b, dataType, err := buildMultipart(values)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &b)
	client := &http.Client{}
	req.Header.Set("Content-Type", dataType)
	req.Header.Set("Accept", "application/json")

	log.Infof("Fetching submission from endpoint: %s", endpoint)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 {
		errObj := JbxErrorObject{}

		if err := json.Unmarshal(body, &errObj); err != nil {
			return fmt.Errorf("Failed reading jbx error(s) from response body: %v", err)
		}
		for _, e := range errObj.Errors {
			log.Error(e.Message)
		}
		return fmt.Errorf("Errors received in JBX response body")
	}
	resObj := JbxAnalysisData{}
	if err = json.Unmarshal(body, &resObj); err != nil {
		return fmt.Errorf("Failed reading data from jbx response body: %v", err)
	}
	if resObj.Data.Status != "finished" {
		log.Infof("%sJbxcloud analysis is incomplete. Come back later!%s", Yellow, Reset)
		return nil
	}
	log.WithFields(log.Fields{
		"detection": resObj.Data.MRA.Detection,
		"score":     resObj.Data.MRA.Score,
	}).Info("Retrieved JBX Result")
	var col string
	switch resObj.Data.MRA.Detection {
	case "malicious":
		col = Red
	case "clean":
		col = Green
	default:
		col = Yellow
	}
	fmt.Fprintf(os.Stdout, "JBXCLOUD SCAN RESULT: %s %s %s\n", col, strings.ToUpper(resObj.Data.MRA.Detection), Reset)
	return nil
}

func vtResults(aUrl, api_key, ep string) error {
	// Endpoint uses a GET request with the submission id in the url, so full endpoint is not yet known
	sid, err := getSubmissionID("vt", aUrl)
	if err != nil {
		return fmt.Errorf("Error fetching VirusTotal submission ID: %v", err)
	}
	log.Infof("retrieved SID: %s", sid)
	endpoint := ep + "/" + sid
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	client := &http.Client{}
	req.Header.Set("x-apikey", api_key)
	req.Header.Set("Accept", "application/json")

	log.Infof("Fetching submission from endpoint: %s", endpoint)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode == 401 {
		errObj := VtErrorObject{}
		if err = json.Unmarshal(body, &errObj); err != nil {
			return fmt.Errorf("Failed reading vt error from response body: %v", err)
		}
		log.Errorf("Virustotal: %s: %s", errObj.Error.Code, errObj.Error.Message)
		return fmt.Errorf("Errors received in VirusTotal response body")
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("Unable to handle status code of %d", res.StatusCode)
	}
	resObj := VtAnalysisData{}
	if err = json.Unmarshal(body, &resObj); err != nil {
		return fmt.Errorf("Failed reading vt analysis data: %v", err)
	}
	log.WithFields(log.Fields{
		"malicious-votes":  resObj.Data.Attributes.LAS.Malicious,
		"suspicious-votes": resObj.Data.Attributes.LAS.Suspicious,
		"harmless-votes":   resObj.Data.Attributes.LAS.Harmless,
		"undetected-votes": resObj.Data.Attributes.LAS.Undetected,
	}).Info("Retrieved VT Result")

	if resObj.Data.Attributes.LAS.Malicious >= 1 {
		log.Warnf("%sURL has one or more malicious votes. Investigate further.%s", Yellow, Reset)
	}
	log.Infof("View more: %s%s", "https://www.virustotal.com/gui/url/", sid)
	return nil

}

func jbxAnalyse(aUrl, endpoint string, values map[string]io.Reader) error {

	b, dataType, err := buildMultipart(values)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &b)
	if err != nil {
		return err
	}
	client := &http.Client{}
	req.Header.Set("Content-Type", dataType)
	req.Header.Set("Accept", "application/json")

	log.Infof("Sending request to endpoint: %s", endpoint)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		errObj := JbxErrorObject{}

		if err := json.Unmarshal(body, &errObj); err != nil {
			return fmt.Errorf("Failed reading jbx error(s) from response body: %v", err)
		}
		for _, e := range errObj.Errors {
			log.Error(e.Message)
		}
		return fmt.Errorf("Errors received in JBX response body")
	}

	resObj := JbxResponseObject{}
	if err = json.Unmarshal(body, &resObj); err != nil {
		return fmt.Errorf("Failed reading data from jbx response body: %v", err)
	}

	configFile, err := getConfigFileName(aUrl)
	if err != nil {
		return fmt.Errorf("Failed to get name of config file: %v", err)
	}
	log.Infof("Received JoeSecurity submission ID of %s. Saving to config file %s", resObj.Data.ID, configFile)
	log.Info("Check results with the 'check-results' subcommand in ~3 minutes.")
	if err = saveData("jbx", configFile, resObj.Data.ID); err != nil {
		return fmt.Errorf("Failed to save JBXCloud submission ID to file: %v", err)
	}
	return nil
}

func buildMultipart(values map[string]io.Reader) (bytes.Buffer, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// Creating form fields for keys and values in request
	log.Info("Creating form from given data")
	for k, v := range values {
		var fw io.Writer
		fw, err := w.CreateFormField(k)
		if err != nil {
			return b, "", err
		}
		if _, err = io.Copy(fw, v); err != nil {
			return b, "", err
		}
	}
	dataType := w.FormDataContentType()
	w.Close()
	return b, dataType, nil
}

func vtAnalyse(aUrl, endpoint, api_key string, values url.Values) error {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("x-apikey", api_key)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode == 401 {
		errObj := VtErrorObject{}
		if err = json.Unmarshal(body, &errObj); err != nil {
			return fmt.Errorf("Failed reading vt error from response body: %v", err)
		}
		log.Errorf("Virustotal: %s: %s", errObj.Error.Code, errObj.Error.Message)
		return fmt.Errorf("Errors received in VirusTotal response body")
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("Unable to handle status code of %d", res.StatusCode)
	}

	resObj := VtResponseObject{}
	if err = json.Unmarshal(body, &resObj); err != nil {
		return fmt.Errorf("Failed reading vt response: %v", err)
	}

	configFile, err := getConfigFileName(aUrl)
	if err != nil {
		return fmt.Errorf("Failed to get name of config file: %v", err)
	}
	log.Infof("Received VirusTotal submission ID of %s. Saving to config file %s", resObj.Data.ID, configFile)
	log.Info("Check results with the 'check-results' subcommand in ~3 minutes.")
	if err = saveData("vt", configFile, strings.Split(resObj.Data.ID, "-")[1]); err != nil {
		return fmt.Errorf("Failed to save VirusTotal submission ID to file: %v", err)
	}
	return nil
}

func saveData(intelpf, configFile, sid string) error {
	platform := Platform{
		Platform: intelpf,
		SID:      sid,
	}
	// check if analysis directory exists
	if _, err := os.Stat("analysis"); err != nil {
		os.Mkdir("analysis", 0644)
	}
	confPath := "analysis/" + configFile
	if _, err := os.Stat(confPath); err != nil {
		if os.IsNotExist(err) {
			var emptyArr []Platform
			emptyStruct := PlatformData{
				Platforms: emptyArr,
			}
			file, err := json.MarshalIndent(emptyStruct, "", "    ")
			if err != nil {
				return fmt.Errorf("couldn't create empty PlatformData obj: %v", err)
			}
			if err = ioutil.WriteFile(confPath, file, 0644); err != nil {
				return fmt.Errorf("couldn't create analysis data file: %v", err)
			}
		} else {
			return err
		}
	}
	jsonFile, err := os.Open(confPath)
	if err != nil {
		return err
	}
	platformData := PlatformData{}
	bytes, _ := ioutil.ReadAll(jsonFile)
	if err = json.Unmarshal(bytes, &platformData); err != nil {
		return fmt.Errorf("Could not unmarshal json from analysis data file: %v", err)
	}
	jsonFile.Close()
	platformData.Platforms = append(platformData.Platforms, platform)
	jsonFile, err = os.Create(confPath)
	f, err := json.MarshalIndent(platformData, "", "    ")
	if err != nil {
		return fmt.Errorf("Couldn't marshal new analysis data: %v", err)
	}
	if err = ioutil.WriteFile(confPath, f, 0644); err != nil {
		return fmt.Errorf("Failed to update data file: %v", err)
	}
	return nil
}

func getSubmissionID(platform, aUrl string) (string, error) {
	configFile, err := getConfigFileName(aUrl)
	if err != nil {
		return "", err
	}
	confPath := "analysis/" + configFile
	if _, err := os.Stat(confPath); err != nil {
		if os.IsNotExist(err) {
			log.Fatal("analysis config file does not exist for URL!")
		} else {
			return "", err
		}
	}
	jsonFile, err := os.Open(confPath)
	if err != nil {
		return "", err
	}
	platformData := PlatformData{}
	bytes, _ := ioutil.ReadAll(jsonFile)
	if err = json.Unmarshal(bytes, &platformData); err != nil {
		return "", fmt.Errorf("Could not unmarshal json from analysis data file: %v", err)
	}
	for _, p := range platformData.Platforms {
		if p.Platform == platform {
			return p.SID, nil
		}
	}
	return "", fmt.Errorf("URL was not previously analysed on this platform")
}

func getConfigFileName(aUrl string) (string, error) {
	hasher := sha1.New()
	_, err := io.WriteString(hasher, strings.TrimSuffix(aUrl, "/"))
	if err != nil {
		return "", err
	}
	configFile := strings.ReplaceAll(
		hex.EncodeToString(hasher.Sum(nil)),
		" ",
		"",
	) + ".json"
	return configFile, nil
}
