// Manual
// https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/

package oauth_github

import (
    "fmt"
    "net/http"
    "strings"
    "github.com/a1div0/oauth"
    "net/url"
    "io/ioutil"
    "encoding/json"
    "time"
)

type OAuthGitHub struct {
    ClientId string
    ClientSecret string
    token string
    token_dt_start time.Time
    redirect_uri string
}

func (s *OAuthGitHub) ServiceName() (string) {
    return "github"
}

func (s *OAuthGitHub) LoginURL(verification_code_callback_url string, state string) (string) {

    s.redirect_uri = verification_code_callback_url

    data := url.Values{}
    data.Set("client_id"    , s.ClientId)
    data.Set("redirect_uri" , verification_code_callback_url)
    data.Set("scope"        , "read:user user:email")
    data.Set("state"        , state)

    return "https://github.com/login/oauth/authorize?" + data.Encode()
}

func (s *OAuthGitHub) OnRecieveVerificationCode(code string, u *oauth.UserData) (error) {

    // Посылаем запрос токена и код подтверждения
    err := s.code_to_token(code)
    if err != nil {
		return err
	}
    err = s.token_to_userdata(u)
    if err != nil {
		return err
	}
    return nil
}

func (s *OAuthGitHub) code_to_token(code string) (error) {

    formData := url.Values{
        "code": {code},
        "client_id": {s.ClientId},
        "client_secret": {s.ClientSecret},
        "redirect_uri": {s.redirect_uri},
	}

    resp, err := http.PostForm("https://github.com/login/oauth/access_token", formData)
	if err != nil {
		return err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return err
    }

    params, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}

    error_text, error_exist := params["error"]
    if (error_exist) { // если пройдёт это условие, значит service_name "чист"
        return fmt.Errorf("Error: %s", strings.Join(error_text, ""))
    }

    tokens, token_exist := params["access_token"]
    if (!token_exist) { // если пройдёт это условие, значит service_name "чист"
        return fmt.Errorf("Error: token not exist!")
    }

    s.token = strings.Join(tokens, "")
    s.token_dt_start = time.Now()

    return nil
}

func (s *OAuthGitHub) token_to_data(url string) ([]byte, error) {
    req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Получаем и устанавливаем тип контента
	req.Header.Set("Authorization", "token " + s.token)

	// Отправляем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
    defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return nil, err
    }

    return body, nil
}

func (s *OAuthGitHub) token_to_userdata(u *oauth.UserData) (error) {

    json_bytes, err := s.token_to_data("https://api.github.com/user")
    if err != nil {
		return err
    }

    type GithubUserAnswerStruct struct {
        Id int64 `json:"id"`
        Login string `json:"login"`
        NodeId string `json:"node_id"`
        AvatarUrl string `json:"avatar_url"`
        Email string `json:"avatar_url"`
    }

    var UserAnswer GithubUserAnswerStruct
    err = json.Unmarshal(json_bytes, &UserAnswer)
    if err != nil {
		return err
    }

    u.ExtId = fmt.Sprintf("%d", UserAnswer.Id)
    u.Name = UserAnswer.Login

    json_bytes, err = s.token_to_data("https://api.github.com/user/emails")
    if err != nil {
		return err
    }

    type GithubEmail struct {
        Email string `json:"email"`
        Primary bool `json:"primary"`
        Verified bool `json:"verified"`
        Visiblity bool `json:"visiblity"`
    }

    var UserEmails []GithubEmail
    err = json.Unmarshal(json_bytes, &UserEmails)
    if err != nil {
		return err
    }

    if (len(UserEmails) < 1) {
        return fmt.Errorf("Error: Email not found!")
    }

    u.Email = UserEmails[0].Email

    return nil
}
