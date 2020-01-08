# mavis_tacplus_aad: Mavis tac_plus plugin to support Azure "AD" Oauth

[![Build Status](https://travis-ci.org/rfdrake/mavis_tacplus_aad.svg?branch=master)](https://travis-ci.org/rfdrake/mavis_tacplus_aad)
[![Coverage Status](https://coveralls.io/repos/github/rfdrake/mavis_tacplus_aad/badge.svg?branch=master)](https://coveralls.io/github/rfdrake/mavis_tacplus_aad?branch=master)

# what this does

This provides an Azure AD oauth backend for the MAVIS tacacs+ daemon.  You might be familiar with traditional active directory, and the way you connect with it for remote authentication.  Most people either use RADIUS or LDAP to talk to backend AD servers.  The cloud "Azure" product is different.  Even though it is a directory and it's referred to as "Active Directory", it doesn't have an LDAP interface.  The only way to talk with it is to use [OAUTH].

You can find the TACACS+ project at [TAC_PLUS]


# HOWTO

To get this working you will need an Azure Active Directory setup.  You can get started by registering and then logging into https://portal.azure.com Once you are logged in you will see the following options.  Click on "Azure Active Directory"

![Azure AD](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_01.png)

Click "App registrations"

![App Registrations](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_02.png)

Click "New registration"

![New Registration](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_03.png)

Give it a name, then select the supported account types.  If you're unsure, then the first option (organizational directory only) is probably the one you want.

You can leave Redirect URI blank, then hit "Register"

![New Registration Page](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_04.png)

Make a note of the Application (client) ID and the Directory (tenant) ID.  You will need them both when setting up your client.  You will also need a "secret" so hit "Certificates & secrets" on the left menu.

![Certs and Secrets](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_05.png)

Then hit "New client secret"

![Certs and Secrets 2](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_06.png)

Then you can specify a description or leave it blank.  You can also set an expiration date or select "Never".  Unless you actively plan to regenerate this and fix your tacacs server every few years, "Never" is probably the best bet.

![Certs and Secrets 3](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_07.png)

At this point the secret value will be displayed.  Make a note of this because it will be needed when configuring the tacacs server.

![Certs and Secrets 4](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_08.png)

At this point you will need to set the permissions to allow "openid".  Click "API permissions"

![API Permissions](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_09.png)

Click "Add a permission"

![API Permissions 2](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_10.png)

Click "Microsoft Graph"

![API Permissions 3](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_11.png)

Click "Delegated permissions", then select "openid", then hit "Add permissions"

![API Permissions 4](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_12.png)

The permissions take a moment before you can authorize them.  Once you get a button that says "Grant admin consent for..." click it.

![API Permissions 5](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_13.png)

Select which account you will use to authorize the OAuth request.  Usually this is the same account you logged into portal.azure.com with.

![API Permissions 6](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_14.png)

Click "Accept"

![API Permissions 7](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_15.png)

In order to use groups you will need to make a couple of additional changes.  If you just plan to use a hardcoded group id, then you will only need to make the manifest change.  If you want to use named groups you will need to add extra API permissions.

Open the manifest

![Manifest 1](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_17.png)

Find the entry that says "groupMembershipClaims" and set it to "All".  If you know what you're doing, you can try using "SecurityGroup" which may limit the list to non-email groups.  I've had better results just setting it to "All".

![Manifest 2](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_18.png)

Finally, you need to add an "Application permission" in the API permissions which allows tacacs to Read all groups.  Click "API Permissions" again, then "Microsoft Graph"

![API Permissions](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_09.png)

This time you need to select "Application permissions".  In the search blank type "Group", then select "Group.Read.All" and hit "Add permissions".

![Group Permissions](https://rfdrake.github.io/mavis_tacplus_aad/azure_ad_19.png)

Follow the same steps as before to grant consent to the application, then confirm the OAuth request.

Your final settings will look like this:

	setenv OAUTH_ENDPOINT = "https://login.microsoftonline.com/<YOUR DIRECTORY ID>/oauth2/v2.0/token"
	setenv OAUTH_CLIENT_ID = "<YOUR CLIENT ID>"
	setenv OAUTH_CLIENT_SECRET = "<YOUR SECRET KEY>"
	setenv OAUTH_DOMAIN = "<YOUR DOMAIN NAME>"

    # for static groups
    setenv OAUTH_GROUP_ID = "<GROUP ID OF ALLOWED USERS>"

    # for named groups
    setenv FLAG_USE_MEMBEROF = 1
    setenv REQUIRE_TACACS_GROUP_PREFIX = 1
    setenv AD_GROUP_PREFIX = "tacacs"
	exec = /usr/local/lib/mavis/mavis_tacplus_aad.pl


# Caching

The Mavis engine can cache data so there won't be as many lookups.  I believe the default is to cache tacplus lookups for 120 seconds.  You can experiment with this.

# Caveats

* All the error messages/codes that we check for might be unique to azure AD.  I'm not sure if there are oauth standards for them.  We might need to make a specific version of this for each OAuth source, or make the error checking more modular so that we can handle different environments.

## groups in JWT tokens

https://stackoverflow.com/questions/36780567/azure-ad-how-to-get-group-information-in-token

The problem with putting the groups in a JWT token is that if a user is a member of > xx groups they will break.  The workaround is that they include a pointer to download the group list.
The limit is around 200 groups.  I don't have someone in >200 groups so I don't know how to code the workaround yet.

## Group and signing key caches are infinite and probably shouldn't be

This means if you change the name of a group from "tacacsAdmins" to "normalUsers" you will need to reload the tacacs daemon for it to see the change.  It also means in the event of the signing key expiring the tacacs server will probably break.  I'm not sure how often this happens.  The key cache is nullified on error, so hopefully this would get taken care of by that, but you might see interim login failures.

# Possible alternatives

I think it would be cleaner to use a PAM backend.  This also allows you to use PAM to do direct server authentication.  I suspect this would be a more supportable solution in the long run.  I'm not positive this is do-able yet because my limited research didn't come across a pam_aad module that does this.  I saw some evidence that Azure supports a PAM module for their Linux virtual machines, but I'm not sure if that is available to the general public to use on remote servers outside of the Azure cloud.


[TAC_PLUS]:     http://www.pro-bono-publico.de/projects/tac_plus.html
[OAUTH]:		https://oauth.net/2
