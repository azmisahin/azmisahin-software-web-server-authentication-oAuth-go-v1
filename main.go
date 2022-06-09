/**
 * @file authentication
 * @author Azmi ŞAHİN (azmisahin@outlook.com)
 * @brief It quickly integrates authentication and authorization processes with application program interfaces to communicate with many protocols such as OAuth.
 * @version 0.0.3
 * @date 2022-01-01
 *
 * @copyright Copyright (c) 2022
 */
package main

import (
	"os"

	authentication "github.com/azmisahin/azmisahin-software-web-server-authentication-oAuth-go-v1/Authentication"
)

func main() {

	PROTOCOL := os.Getenv("PROTOCOL")
	DOMAIN := os.Getenv("DOMAIN_NAME")
	PORT := os.Getenv("AUTHENTICATION_SERVER_APP_PORT")

	app := authentication.NewAuthentication()
	app.Start(PROTOCOL, DOMAIN, PORT)
}
