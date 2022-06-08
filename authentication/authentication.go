/**
 * @file authentication.go
 * @author Azmi ŞAHİN (azmisahin@outlook.com)
 * @brief It quickly integrates authentication and authorization processes with application program interfaces to communicate with many protocols such as OAuth.
 * @version 0.0.2
 * @date 2022-01-01
 *
 * @copyright Copyright (c) 2022
 */
package authentication

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/amazon"
	"github.com/markbates/goth/providers/apple"
	"github.com/markbates/goth/providers/auth0"
	"github.com/markbates/goth/providers/azuread"
	"github.com/markbates/goth/providers/battlenet"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/markbates/goth/providers/box"
	"github.com/markbates/goth/providers/dailymotion"
	"github.com/markbates/goth/providers/deezer"
	"github.com/markbates/goth/providers/digitalocean"
	"github.com/markbates/goth/providers/discord"
	"github.com/markbates/goth/providers/dropbox"
	"github.com/markbates/goth/providers/eveonline"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/fitbit"
	"github.com/markbates/goth/providers/gitea"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/gplus"
	"github.com/markbates/goth/providers/heroku"
	"github.com/markbates/goth/providers/instagram"
	"github.com/markbates/goth/providers/intercom"
	"github.com/markbates/goth/providers/kakao"
	"github.com/markbates/goth/providers/lastfm"
	"github.com/markbates/goth/providers/line"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/markbates/goth/providers/mastodon"
	"github.com/markbates/goth/providers/meetup"
	"github.com/markbates/goth/providers/microsoftonline"
	"github.com/markbates/goth/providers/naver"
	"github.com/markbates/goth/providers/nextcloud"
	"github.com/markbates/goth/providers/okta"
	"github.com/markbates/goth/providers/onedrive"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/markbates/goth/providers/paypal"
	"github.com/markbates/goth/providers/salesforce"
	"github.com/markbates/goth/providers/seatalk"
	"github.com/markbates/goth/providers/shopify"
	"github.com/markbates/goth/providers/slack"
	"github.com/markbates/goth/providers/soundcloud"
	"github.com/markbates/goth/providers/spotify"
	"github.com/markbates/goth/providers/steam"
	"github.com/markbates/goth/providers/strava"
	"github.com/markbates/goth/providers/stripe"
	"github.com/markbates/goth/providers/tiktok"
	"github.com/markbates/goth/providers/twitch"
	"github.com/markbates/goth/providers/twitter"
	"github.com/markbates/goth/providers/typetalk"
	"github.com/markbates/goth/providers/uber"
	"github.com/markbates/goth/providers/vk"
	"github.com/markbates/goth/providers/wecom"
	"github.com/markbates/goth/providers/wepay"
	"github.com/markbates/goth/providers/xero"
	"github.com/markbates/goth/providers/yahoo"
	"github.com/markbates/goth/providers/yammer"
	"github.com/markbates/goth/providers/yandex"
	"github.com/markbates/goth/providers/zoom"
)

// Authentication
type Authentication struct {
}

// New Authentication
func NewAuthentication() *Authentication {

	//
	return &Authentication{}
}

// Authentication
// PROTOCOL="http"
// DOMAIN="localhost"
// PORT="10703"
func (authentication *Authentication) Start(PROTOCOL string, DOMAIN string, PORT string) {

	goth.UseProviders(
		twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/twitter/callback"),
		// If you'd like to use authenticate instead of authorize in Twitter provider, use this instead.
		// twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), PROTOCOL + "://" + DOMAIN + ":" + PORT + "/auth/twitter/callback"),

		tiktok.New(os.Getenv("TIKTOK_KEY"), os.Getenv("TIKTOK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/tiktok/callback"),
		facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/facebook/callback"),
		fitbit.New(os.Getenv("FITBIT_KEY"), os.Getenv("FITBIT_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/fitbit/callback"),
		google.New(os.Getenv("GOOGLE_KEY"), os.Getenv("GOOGLE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/google/callback"),
		gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/gplus/callback"),
		github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/github/callback"),
		spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/spotify/callback"),
		linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/linkedin/callback"),
		line.New(os.Getenv("LINE_KEY"), os.Getenv("LINE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/line/callback", "profile", "openid", "email"),
		lastfm.New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/lastfm/callback"),
		twitch.New(os.Getenv("TWITCH_KEY"), os.Getenv("TWITCH_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/twitch/callback"),
		dropbox.New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/dropbox/callback"),
		digitalocean.New(os.Getenv("DIGITALOCEAN_KEY"), os.Getenv("DIGITALOCEAN_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/digitalocean/callback", "read"),
		bitbucket.New(os.Getenv("BITBUCKET_KEY"), os.Getenv("BITBUCKET_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/bitbucket/callback"),
		instagram.New(os.Getenv("INSTAGRAM_KEY"), os.Getenv("INSTAGRAM_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/instagram/callback"),
		intercom.New(os.Getenv("INTERCOM_KEY"), os.Getenv("INTERCOM_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/intercom/callback"),
		box.New(os.Getenv("BOX_KEY"), os.Getenv("BOX_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/box/callback"),
		salesforce.New(os.Getenv("SALESFORCE_KEY"), os.Getenv("SALESFORCE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/salesforce/callback"),
		seatalk.New(os.Getenv("SEATALK_KEY"), os.Getenv("SEATALK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/seatalk/callback"),
		amazon.New(os.Getenv("AMAZON_KEY"), os.Getenv("AMAZON_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/amazon/callback"),
		yammer.New(os.Getenv("YAMMER_KEY"), os.Getenv("YAMMER_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/yammer/callback"),
		onedrive.New(os.Getenv("ONEDRIVE_KEY"), os.Getenv("ONEDRIVE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/onedrive/callback"),
		azuread.New(os.Getenv("AZUREAD_KEY"), os.Getenv("AZUREAD_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/azuread/callback", nil),
		microsoftonline.New(os.Getenv("MICROSOFTONLINE_KEY"), os.Getenv("MICROSOFTONLINE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/microsoftonline/callback"),
		battlenet.New(os.Getenv("BATTLENET_KEY"), os.Getenv("BATTLENET_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/battlenet/callback"),
		eveonline.New(os.Getenv("EVEONLINE_KEY"), os.Getenv("EVEONLINE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/eveonline/callback"),
		kakao.New(os.Getenv("KAKAO_KEY"), os.Getenv("KAKAO_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/kakao/callback"),

		//Pointed " + DOMAIN + ".com to http://" + DOMAIN + ":" + PORT + "/auth/yahoo/callback through proxy as yahoo
		// does not allow to put custom ports in redirection uri
		yahoo.New(os.Getenv("YAHOO_KEY"), os.Getenv("YAHOO_SECRET"), PROTOCOL+"://"+DOMAIN),
		typetalk.New(os.Getenv("TYPETALK_KEY"), os.Getenv("TYPETALK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/typetalk/callback", "my"),
		slack.New(os.Getenv("SLACK_KEY"), os.Getenv("SLACK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/slack/callback"),
		stripe.New(os.Getenv("STRIPE_KEY"), os.Getenv("STRIPE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/stripe/callback"),
		wepay.New(os.Getenv("WEPAY_KEY"), os.Getenv("WEPAY_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/wepay/callback", "view_user"),
		//By default paypal production auth urls will be used, please set PAYPAL_ENV=sandbox as environment variable for testing
		//in sandbox environment
		paypal.New(os.Getenv("PAYPAL_KEY"), os.Getenv("PAYPAL_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/paypal/callback"),
		steam.New(os.Getenv("STEAM_KEY"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/steam/callback"),
		heroku.New(os.Getenv("HEROKU_KEY"), os.Getenv("HEROKU_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/heroku/callback"),
		uber.New(os.Getenv("UBER_KEY"), os.Getenv("UBER_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/uber/callback"),
		soundcloud.New(os.Getenv("SOUNDCLOUD_KEY"), os.Getenv("SOUNDCLOUD_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/soundcloud/callback"),
		gitlab.New(os.Getenv("GITLAB_KEY"), os.Getenv("GITLAB_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/gitlab/callback"),
		dailymotion.New(os.Getenv("DAILYMOTION_KEY"), os.Getenv("DAILYMOTION_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/dailymotion/callback", "email"),
		deezer.New(os.Getenv("DEEZER_KEY"), os.Getenv("DEEZER_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/deezer/callback", "email"),
		discord.New(os.Getenv("DISCORD_KEY"), os.Getenv("DISCORD_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/discord/callback", discord.ScopeIdentify, discord.ScopeEmail),
		meetup.New(os.Getenv("MEETUP_KEY"), os.Getenv("MEETUP_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/meetup/callback"),

		//Auth0 allocates domain per customer, a domain must be provided for auth0 to work
		auth0.New(os.Getenv("AUTH0_KEY"), os.Getenv("AUTH0_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/auth0/callback", os.Getenv("AUTH0_DOMAIN")),
		xero.New(os.Getenv("XERO_KEY"), os.Getenv("XERO_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/xero/callback"),
		vk.New(os.Getenv("VK_KEY"), os.Getenv("VK_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/vk/callback"),
		naver.New(os.Getenv("NAVER_KEY"), os.Getenv("NAVER_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/naver/callback"),
		yandex.New(os.Getenv("YANDEX_KEY"), os.Getenv("YANDEX_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/yandex/callback"),
		nextcloud.NewCustomisedDNS(os.Getenv("NEXTCLOUD_KEY"), os.Getenv("NEXTCLOUD_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/nextcloud/callback", os.Getenv("NEXTCLOUD_URL")),
		gitea.New(os.Getenv("GITEA_KEY"), os.Getenv("GITEA_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/gitea/callback"),
		shopify.New(os.Getenv("SHOPIFY_KEY"), os.Getenv("SHOPIFY_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/shopify/callback", shopify.ScopeReadCustomers, shopify.ScopeReadOrders),
		apple.New(os.Getenv("APPLE_KEY"), os.Getenv("APPLE_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/apple/callback", nil, apple.ScopeName, apple.ScopeEmail),
		strava.New(os.Getenv("STRAVA_KEY"), os.Getenv("STRAVA_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/strava/callback"),
		okta.New(os.Getenv("OKTA_ID"), os.Getenv("OKTA_SECRET"), os.Getenv("OKTA_ORG_URL"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/okta/callback", "openid", "profile", "email"),
		mastodon.New(os.Getenv("MASTODON_KEY"), os.Getenv("MASTODON_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/mastodon/callback", "read:accounts"),
		wecom.New(os.Getenv("WECOM_CORP_ID"), os.Getenv("WECOM_SECRET"), os.Getenv("WECOM_AGENT_ID"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/wecom/callback"),
		zoom.New(os.Getenv("ZOOM_KEY"), os.Getenv("ZOOM_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/zoom/callback", "read:user"),
	)

	// OpenID Connect is based on OpenID Connect Auto Discovery URL (https://openid.net/specs/openid-connect-discovery-1_0-17.html)
	// because the OpenID Connect provider initialize it self in the New(), it can return an error which should be handled or ignored
	// ignore the error for now
	openidConnect, _ := openidConnect.New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), PROTOCOL+"://"+DOMAIN+":"+PORT+"/auth/openid-connect/callback", os.Getenv("OPENID_CONNECT_DISCOVERY_URL"))
	if openidConnect != nil {
		goth.UseProviders(openidConnect)
	}

	m := make(map[string]string)
	m["amazon"] = "Amazon"
	m["bitbucket"] = "Bitbucket"
	m["box"] = "Box"
	m["dailymotion"] = "Dailymotion"
	m["deezer"] = "Deezer"
	m["digitalocean"] = "Digital Ocean"
	m["discord"] = "Discord"
	m["dropbox"] = "Dropbox"
	m["eveonline"] = "Eve Online"
	m["facebook"] = "Facebook"
	m["fitbit"] = "Fitbit"
	m["gitea"] = "Gitea"
	m["github"] = "Github"
	m["gitlab"] = "Gitlab"
	m["google"] = "Google"
	m["gplus"] = "Google Plus"
	m["shopify"] = "Shopify"
	m["soundcloud"] = "SoundCloud"
	m["spotify"] = "Spotify"
	m["steam"] = "Steam"
	m["stripe"] = "Stripe"
	m["tiktok"] = "TikTok"
	m["twitch"] = "Twitch"
	m["uber"] = "Uber"
	m["wepay"] = "Wepay"
	m["yahoo"] = "Yahoo"
	m["yammer"] = "Yammer"
	m["heroku"] = "Heroku"
	m["instagram"] = "Instagram"
	m["intercom"] = "Intercom"
	m["kakao"] = "Kakao"
	m["lastfm"] = "Last FM"
	m["linkedin"] = "Linkedin"
	m["line"] = "LINE"
	m["onedrive"] = "Onedrive"
	m["azuread"] = "Azure AD"
	m["microsoftonline"] = "Microsoft Online"
	m["battlenet"] = "Battlenet"
	m["paypal"] = "Paypal"
	m["twitter"] = "Twitter"
	m["salesforce"] = "Salesforce"
	m["typetalk"] = "Typetalk"
	m["slack"] = "Slack"
	m["meetup"] = "Meetup.com"
	m["auth0"] = "Auth0"
	m["openid-connect"] = "OpenID Connect"
	m["xero"] = "Xero"
	m["vk"] = "VK"
	m["naver"] = "Naver"
	m["yandex"] = "Yandex"
	m["nextcloud"] = "NextCloud"
	m["seatalk"] = "SeaTalk"
	m["apple"] = "Apple"
	m["strava"] = "Strava"
	m["okta"] = "Okta"
	m["mastodon"] = "Mastodon"
	m["wecom"] = "WeCom"
	m["zoom"] = "Zoom"

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	p := pat.New()
	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {

		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(res, user)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.Logout(res, req)
		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})

	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		// try to get the user without re-authenticating
		if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
			t, _ := template.New("foo").Parse(userTemplate)
			t.Execute(res, gothUser)
		} else {
			gothic.BeginAuthHandler(res, req)
		}
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, providerIndex)
	})
	portSring := ":" + PORT
	log.Println("authentication-server\t✅\t", PROTOCOL, DOMAIN, PORT)
	log.Fatal(http.ListenAndServe(portSring, p))
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.Providers}}
    "provider":"{{$value}}"
{{end}}`

var userTemplate = `
{
	"provider":"{{.Provider}}",
	"name":"{{.Name}}",
	"first_name":"{{.FirstName}}",
	"last_name":"{{.LastName}}",
	"nick_name":"{{.NickName}}",
	"user_id":"{{.UserID}}",
	"email_address":"{{.Email}}",
	"location":"{{.Location}}",
	"avatar":"{{.AvatarURL}}",
	"description":"{{.Description}}",
	"access_token":"{{.AccessToken}}",
	"expires_at":"{{.ExpiresAt}}",
	"refresh_token":"{{.RefreshToken}}"
}
`
