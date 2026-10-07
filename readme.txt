=== Lightweight Email 2FA ===
Contributors: rajivaryal
Tags: two-factor, 2fa, security, login, email
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Simple, lightweight two-factor authentication. After the password is accepted, a one-time code is emailed to the user.

== Description ==

Lightweight Email 2FA adds a second login step to WordPress without apps, phone numbers or external services. After a user enters the correct username and password, a 6-digit code is sent to the email address on their account. The user is logged in only after entering that code.

**Features**

* Works with the standard WordPress login screen (wp-login.php).
* Users can turn it on from their own profile.
* Administrators can require it for selected roles (for example Administrator and Editor).
* Configurable code expiry (default 10 minutes).
* No external services, no tracking, no database tables, no JavaScript or CSS loaded on the front end.
* Removes all of its data when deleted.

**Security**

* Codes are generated with a cryptographically secure random number generator.
* Codes and session tokens are stored only as keyed hashes (HMAC-SHA256), never in plain text.
* The password-only session created by WordPress is destroyed before the code step, so no cookie is valid until the code is verified.
* A code is invalidated after 5 wrong attempts; 10 wrong attempts within 15 minutes temporarily lock the account's code step.
* Resending is limited (60-second cooldown, 3 resends per login).
* Password logins over XML-RPC are blocked for users with 2FA. Application passwords keep working.

**Requirements**

Your site must be able to send email. If email is unreliable on your host, use an SMTP plugin before enforcing 2FA.

== Installation ==

1. Upload the `lightweight-email-2fa` folder to `/wp-content/plugins/`, or install it from the Plugins screen.
2. Activate the plugin.
3. Go to **Settings > Email 2FA** to require it for roles, or let each user enable it under **Users > Profile**.

== Frequently Asked Questions ==

= I am locked out because email is not arriving. What can I do? =

Add the following line to `wp-config.php` to temporarily skip the code step:

`define( 'LWE2FA_DISABLE', true );`

Log in, fix your email setup, then remove the line.

= Does it work with custom or front-end login forms? =

Any login that goes through `wp_signon()` (which fires the `wp_login` action) is redirected to the verification screen on wp-login.php.

= Can I change the email text? =

Yes, use the `lwe2fa_email_subject` and `lwe2fa_email_message` filters.

= Can I control who needs 2FA from code? =

Use the `lwe2fa_enabled_for_user` filter, which receives the current decision and the `WP_User` object.

== Changelog ==

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
