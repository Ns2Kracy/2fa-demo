package main

import (
	"encoding/base64"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

func main() {
	e := echo.New()

	e.GET("/generate-2fa", Generate2FA)
	e.POST("/validate-2fa", Validate2FA)

	e.Logger.Fatal(e.Start(":1323"))
}

func Generate2FA(c echo.Context) error {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Demo",
		AccountName: "user@example.com",
	})
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	otpURL := key.URL()

	png, err := qrcode.Encode(otpURL, qrcode.Medium, 256)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	encodingPng := base64.StdEncoding.EncodeToString(png)

	return c.JSON(http.StatusOK, map[string]string{
		"secret": key.Secret(),
		"url":    otpURL,
		"qrcode": "data:image/png;base64," + encodingPng,
	})
}

func Validate2FA(c echo.Context) error {
	json := make(map[string]string)

	if err := c.Bind(&json); err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	secret := json["secret"]
	code := json["code"]

	valid := totp.Validate(code, secret)

	if !valid {
		return c.String(http.StatusUnauthorized, "Invalid")
	}

	return c.String(http.StatusOK, "Valid")
}
